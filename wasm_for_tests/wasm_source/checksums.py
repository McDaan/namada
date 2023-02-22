import json
import glob
import hashlib
import os

checksums = {}
for wasm in sorted(glob.glob("../*.wasm")):
    basename = os.path.basename(wasm)
    file_name = (
        os.path.splitext(basename)[0]
        if wasm.count(".") == 1
        else os.path.splitext(basename)[0].split(".")[0]
    )
    checksums["{}.wasm".format(file_name)] = "{}.{}.wasm".format(
        file_name, hashlib.sha256(open(wasm, "rb").read()).hexdigest()
    )

updated_wasms = list(checksums.values())

json.dump(checksums, open("../checksums.json", "w+"), indent=4, sort_keys=True)
