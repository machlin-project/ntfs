"""Receive only reviewed detached test images from one dedicated VM peer.

The receiver supplies artifact transport, never filesystem recovery. A native
collector's exact post-detach hash authorizes each bounded image. A successful
receipt follows complete byte/hash verification and persistence on the host.
The caller may then release its generated guest copy after separate native
plain-file, detached-state and unchanged-hash checks.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import threading
import zlib

TRANSFER_CHUNK_BYTES = 1024 * 1024
TRANSFER_TIMEOUT_SECONDS = 120
MAX_BATCH_IMAGES = 12
GZIP_HEADER_FLAG = 16
CASE_PATTERN = re.compile(r'[A-Za-z0-9-]{1,80}')
HASH_PATTERN = re.compile(r'[a-f0-9]{64}')


class ImageArchiveReceiver:
    def __init__(self, directory, bind_address, peer_address, expected, max_bytes):
        self.directory = Path(directory)
        assert self.directory.is_dir() and not self.directory.is_symlink()
        assert 1 <= len(expected) <= MAX_BATCH_IMAGES and max_bytes > 0
        assert all(CASE_PATTERN.fullmatch(case) and HASH_PATTERN.fullmatch(digest)
            for case, digest in expected.items())
        self.expected = dict(expected)
        self.max_bytes = max_bytes
        self.peer_address = peer_address
        self.receipts, self.errors, self.attempted = {}, [], set()
        self.lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *arguments):
                pass

            def reply(self, status, result):
                content = (json.dumps(result) + '\n').encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def do_PUT(self):
                case = self.path.removeprefix('/images/')
                if (self.client_address[0] != receiver.peer_address or
                    self.path != '/images/' + case or case not in receiver.expected or
                    self.headers.get('Transfer-Encoding') is not None):
                    self.reply(403, dict(success=False, error='Unexpected peer, route or transfer encoding'))
                    return
                length = self.headers.get('Content-Length', '')
                if not re.fullmatch(r'[1-9][0-9]{0,9}', length) or int(length) > receiver.max_bytes:
                    self.reply(413, dict(success=False, error='Image length outside reviewed bound'))
                    return
                encoding = self.headers.get('Content-Encoding')
                image_length = self.headers.get('X-Native-Image-Length', length)
                if (encoding not in (None, 'gzip') or
                    not re.fullmatch(r'[1-9][0-9]{0,9}', image_length) or
                    int(image_length) > receiver.max_bytes or
                    (encoding is None and image_length != length)):
                    self.reply(413, dict(success=False, error='Image encoding or decoded length outside reviewed bound'))
                    return
                with receiver.lock:
                    if case in receiver.attempted:
                        self.reply(409, dict(success=False, error='An image invocation must not repeat'))
                        return
                    receiver.attempted.add(case)
                remaining = int(length)
                image_remaining = int(image_length)
                decoder = zlib.decompressobj(zlib.MAX_WBITS + GZIP_HEADER_FLAG) if encoding else None
                temporary = receiver.directory / (case + '.uploading')
                destination = receiver.directory / (case + '.native.vhd')
                digest = hashlib.sha256()
                try:
                    self.connection.settimeout(TRANSFER_TIMEOUT_SECONDS)
                    with temporary.open('xb') as output:
                        while remaining:
                            value = self.rfile.read(min(remaining, TRANSFER_CHUNK_BYTES))
                            if not value:
                                raise RuntimeError('Native image transfer ended before its declared length')
                            remaining -= len(value)
                            while value:
                                if decoder is not None:
                                    restored = decoder.decompress(value,
                                        min(TRANSFER_CHUNK_BYTES, image_remaining + 1))
                                    value = decoder.unconsumed_tail
                                    if decoder.unused_data:
                                        raise RuntimeError('Unexpected bytes after the complete gzip stream')
                                else:
                                    restored, value = value, b''
                                if len(restored) > image_remaining:
                                    raise RuntimeError('Decoded image exceeds its declared bound')
                                output.write(restored)
                                digest.update(restored)
                                image_remaining -= len(restored)
                        if image_remaining or (decoder is not None and not decoder.eof):
                            raise RuntimeError('Decoded image or gzip trailer is incomplete')
                        if digest.hexdigest() != receiver.expected[case]:
                            raise RuntimeError('Native image differs from its collector post-detach hash')
                        output.flush()
                        os.fsync(output.fileno())
                        if hasattr(fcntl, 'F_FULLFSYNC'):
                            fcntl.fcntl(output.fileno(), fcntl.F_FULLFSYNC)
                    # link() refuses an existing destination, including a symlink.
                    os.link(temporary, destination)
                    temporary.unlink()
                    destination.chmod(0o444)
                    receipt = dict(case=case, bytes=int(image_length), sha256=digest.hexdigest(),
                        path=str(destination), persisted=True, wireBytes=int(length),
                        contentEncoding=encoding or 'identity')
                    with receiver.lock:
                        receiver.receipts[case] = receipt
                    (receiver.directory / (case + '.archive-receipt.json')).write_text(
                        json.dumps(receipt, indent=2) + '\n')
                    self.reply(200, dict(receipt, success=True))
                except BaseException as error:
                    record = dict(case=case, error=repr(error), destination=str(destination),
                        partial=str(temporary), automaticRetry=False)
                    with receiver.lock:
                        receiver.errors.append(record)
                    (receiver.directory / (case + '.archive-error.json')).write_text(
                        json.dumps(record, indent=2) + '\n')
                    self.reply(500, dict(success=False, error=str(error)))

        self.server = ThreadingHTTPServer((bind_address, 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self):
        host, port = self.server.server_address
        return f'http://{host}:{port}'

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *arguments):
        self.server.shutdown()
        self.thread.join(timeout=TRANSFER_TIMEOUT_SECONDS + 1)
        self.server.server_close()


def upload_body(guest_manifest, guest_directory, endpoint, compressed=True):
    """One prepared invocation uploads already detached, SHA-bound native images.

    Paths and endpoint are main-authored private harness values; none is derived
    from NTFS bytes. The caller retains the wrapper and native returned receipts.
    This function never creates, mounts, repairs or removes a guest image.
    """
    assert "'" not in guest_manifest + guest_directory + endpoint
    body = "$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$r.uploaded=@();"
    body += "$m=Get-Content -LiteralPath '" + guest_manifest + "' -Raw|ConvertFrom-Json;$d='" + guest_directory + "';"
    body += "if(@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or (Test-Path -LiteralPath 'R:\\')){throw 'Candidate letter remains active'};"
    body += "foreach($i in $m.images){if($i.case -notmatch '^[A-Za-z0-9-]{1,80}$'){throw 'Unexpected archive image name'};"
    body += "$p=Join-Path $d ($i.case+'.vhd');$f=Get-Item -LiteralPath $p;"
    body += "if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-DiskImage -ImagePath $p).Attached){throw 'Plain detached image required'};"
    body += "if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $i.sha256){throw 'Detached native image hash changed'};"
    if compressed:
        body += "$wire=$p+'.transfer.gz';$packedOutput=[IO.File]::Open($wire,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);"
        body += "try{$imageInput=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);"
        body += "try{$gzip=[IO.Compression.GZipStream]::new($packedOutput,[IO.Compression.CompressionLevel]::Optimal,$true);try{$imageInput.CopyTo($gzip)}finally{$gzip.Dispose()}}finally{$imageInput.Dispose()};$packedOutput.Flush($true)}finally{$packedOutput.Dispose()};"
        body += "$wireBytes=(Get-Item -LiteralPath $wire).Length;"
    else:
        body += "$wire=$p;$wireBytes=$f.Length;"
    body += "$q=[Net.HttpWebRequest]::Create('" + endpoint + "/images/'+$i.case);$q.Method='PUT';$q.Proxy=$null;$q.AllowWriteStreamBuffering=$false;"
    body += "$q.ContentType='application/octet-stream';$q.ContentLength=$wireBytes;$q.Timeout=120000;$q.ReadWriteTimeout=120000;"
    if compressed:
        body += "$q.Headers['Content-Encoding']='gzip';$q.Headers['X-Native-Image-Length']=$f.Length.ToString([Globalization.CultureInfo]::InvariantCulture);"
    body += "$imageInput=[IO.File]::Open($wire,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);"
    body += "try{$imageOutput=$q.GetRequestStream();try{$imageInput.CopyTo($imageOutput)}finally{$imageOutput.Dispose()}}finally{$imageInput.Dispose()};"
    body += "$response=$q.GetResponse();try{$reader=[IO.StreamReader]::new($response.GetResponseStream());try{$receipt=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}}finally{$response.Dispose()};"
    body += "if(!$receipt.success -or !$receipt.persisted -or $receipt.case -ne $i.case -or $receipt.sha256 -ne $i.sha256 -or $receipt.bytes -ne $f.Length){throw 'Native host archive receipt disagrees'};"
    body += "$r.uploaded+=@{case=$i.case;sha256=$receipt.sha256;bytes=$receipt.bytes}}"
    return body


def release_body(guest_manifest, guest_directory):
    """Release only generated copies whose full detached images are archived.

    The main caller has verified every persisted host receipt and exact image
    hash. Native checks below re-prove plain-file, detached and unchanged source
    state for the complete group before any removal. Original test volumes and
    unrelated fixture paths are never operands.
    """
    assert "'" not in guest_manifest + guest_directory
    body = "$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$r.removed=@();"
    body += "$m=Get-Content -LiteralPath '" + guest_manifest + "' -Raw|ConvertFrom-Json;$d='" + guest_directory + "';"
    body += "if(@(Get-Partition -DriveLetter R -ErrorAction SilentlyContinue).Count -ne 0 -or (Test-Path -LiteralPath 'R:\\')){throw 'Candidate letter remains active'};"
    body += "foreach($i in $m.images){if($i.case -notmatch '^[A-Za-z0-9-]{1,80}$'){throw 'Unexpected retained image name'};"
    body += "$p=Join-Path $d ($i.case+'.vhd');if($p -ne $i.guestPath){throw 'Retained fixture path disagrees'};"
    body += "$f=Get-Item -LiteralPath $p;if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -ne $i.bytes){throw 'Retained fixture identity changed'};"
    body += "if((Get-DiskImage -ImagePath $p).Attached){throw 'Retained fixture still attached'};"
    body += "if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne $i.sha256){throw 'Retained fixture hash changed'};"
    body += "if($i.contentEncoding -eq 'gzip'){$wire=Get-Item -LiteralPath ($p+'.transfer.gz');if($wire.PSIsContainer -or ($wire.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $wire.Length -ne $i.wireBytes){throw 'Generated compressed copy changed'}}};"
    body += "foreach($i in $m.images){$p=Join-Path $d ($i.case+'.vhd');"
    body += "if($i.contentEncoding -eq 'gzip'){Remove-Item -LiteralPath ($p+'.transfer.gz')};Remove-Item -LiteralPath $p;"
    body += "if(Test-Path -LiteralPath $p){throw 'Owned detached copy removal unobserved'};$r.removed+=@{case=$i.case;sha256=$i.sha256;bytes=$i.bytes}}"
    return body
