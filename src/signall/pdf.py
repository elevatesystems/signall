"""Low-level PDF helpers shared by the inspection and signing code."""
from __future__ import annotations

import functools
import hashlib
import io
import sys

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader


class SignallError(Exception):
    """An error with a message suitable for end users."""


def _allow_md5_for_pdf_encryption() -> None:
    """Let legacy PDF encryption (which derives keys with MD5) work on FIPS hosts.

    The MD5 use here is part of the PDF standard security handler, not a
    security decision of ours, so it is marked ``usedforsecurity=False``.
    """
    md5 = functools.partial(hashlib.md5, usedforsecurity=False)
    for name, module in list(sys.modules.items()):
        if name.startswith("pyhanko") and getattr(module, "md5", None) is hashlib.md5:
            module.md5 = md5


def open_reader(data: bytes) -> PdfFileReader:
    """Open a PDF for reading, unlocking it if it uses an empty user password."""
    reader = PdfFileReader(io.BytesIO(data), strict=False)
    if reader.encrypted:
        _allow_md5_for_pdf_encryption()
        _install_exempt_string_fallback()
        try:
            reader.decrypt("")
        except Exception as exc:  # pragma: no cover - depends on the file
            raise SignallError("this PDF is password-protected; Signall can't open it") from exc
    return reader


class _VerbatimBytes(generic.ByteStringObject):
    """A string that is never encrypted on output (signature /Contents are exempt)."""

    def write_to_stream(self, stream, handler=None, container_ref=None):
        super().write_to_stream(stream, None, container_ref)


_FALLBACK_INSTALLED = False


def _install_exempt_string_fallback() -> None:
    """Treat strings that cannot be decrypted as encryption-exempt.

    Signature ``/Contents`` are never encrypted. pyHanko knows this for
    signature objects it reads directly, but not when it compares catalogs
    between revisions (for example with Adobe's usage-rights signature inside
    an encrypted catalog), where it would crash. A string that fails to
    decrypt is kept verbatim, and is also written back verbatim.
    """
    global _FALLBACK_INSTALLED
    if _FALLBACK_INSTALLED:
        return
    original = generic.DecryptedObjectProxy.decrypted

    def decrypted(self):
        try:
            return original.fget(self)
        except ValueError:
            raw = self.raw_object
            if not isinstance(raw, (generic.ByteStringObject, generic.TextStringObject)):
                raise
            value = _VerbatimBytes(raw.original_bytes)
            value.container_ref = raw.container_ref
            self._decrypted = value
            return value

    generic.DecryptedObjectProxy.decrypted = property(decrypted)
    _FALLBACK_INSTALLED = True


def _keep_usage_rights_intact(writer: IncrementalPdfFileWriter) -> None:
    """Make Adobe's usage-rights signature survive a rewrite of an encrypted catalog.

    ``/Perms /UR3`` is usually a direct object inside the catalog. Its
    ``/Contents`` is stored unencrypted (as for every signature), so it must be
    copied byte for byte instead of being decrypted and re-encrypted.
    """
    root = writer.root
    if "/Perms" not in root or isinstance(root.raw_get("/Perms"), generic.IndirectObject):
        return
    perms = root["/Perms"]
    ur3_raw = perms.raw_get("/UR3")
    if ur3_raw is None or isinstance(ur3_raw, generic.IndirectObject):
        return
    encrypted_form = ur3_raw.raw_object if isinstance(ur3_raw, generic.DecryptedObjectProxy) else ur3_raw
    contents = dict.get(encrypted_form, "/Contents")  # the stored value, without decrypting it
    contents = contents.raw_object if isinstance(contents, generic.DecryptedObjectProxy) else contents
    ur3 = ur3_raw.get_object()
    fixed = generic.DictionaryObject({k: ur3.raw_get(k) for k in ur3 if k != "/Contents"})
    fixed[generic.NameObject("/Contents")] = _VerbatimBytes(contents.original_bytes)
    new_perms = generic.DictionaryObject({k: perms.raw_get(k) for k in perms})
    new_perms[generic.NameObject("/UR3")] = fixed
    root[generic.NameObject("/Perms")] = new_perms
    writer.update_root()


def open_writer(data: bytes) -> IncrementalPdfFileWriter:
    """Open a PDF for an incremental update, unlocking an empty user password."""
    writer = IncrementalPdfFileWriter(io.BytesIO(data), strict=False)
    if writer.prev.encrypted:
        _allow_md5_for_pdf_encryption()
        _install_exempt_string_fallback()
        writer.encrypt("")
        _keep_usage_rights_intact(writer)
    return writer


def name(value: str) -> generic.NameObject:
    return generic.NameObject(value if value.startswith("/") else "/" + value)


def rect(values) -> generic.ArrayObject:
    return generic.ArrayObject(generic.FloatObject(round(float(v), 3)) for v in values)


def get(obj, key: str, default=None):
    """Like ``dict.get`` but resolves indirect references (pyHanko's ``get`` does not)."""
    if obj is None:
        return default
    obj = obj.get_object() if isinstance(obj, generic.IndirectObject) else obj
    return obj[key] if key in obj else default
