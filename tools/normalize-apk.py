#!/usr/bin/env python3
"""Normalize unsigned ZIP timestamps before zipalign/signing; payload bytes stay intact."""
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
import zipfile

def normalize(path, epoch):
    stamp = datetime.fromtimestamp(int(epoch), timezone.utc)
    if not 1980 <= stamp.year <= 2107:
        raise ValueError('SOURCE_DATE_EPOCH outside ZIP timestamp range')
    temp = path.with_suffix('.normalized')
    try:
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(temp, 'x') as dst:
            names = src.namelist()
            if len(set(names)) != len(names): raise ValueError('duplicate ZIP entry')
            for name in sorted(names):
                if name.startswith('META-INF/') and name.upper().endswith(('.RSA','.DSA','.EC','.SF')):
                    raise ValueError('normalize only unsigned APKs')
                info = src.getinfo(name)
                info.date_time = (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)
                dst.writestr(info, src.read(name))
        os.replace(temp, path)
    finally:
        if temp.exists(): temp.unlink()

if __name__ == '__main__': normalize(Path(sys.argv[1]), sys.argv[2])
