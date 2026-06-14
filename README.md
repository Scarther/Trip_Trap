# Trip_Trap
Your Tripwire Creator

Change the name of the frontcache script to hide better in your system. 

# How It Works

Both scripts take an already saved file, whether its an image, txt, csv, or other types of tripwire wiles. Input the path of the file you want to turn into a tripwire, input your canary token, and the path you want the file to be. The original file is deleted so the only one left is the tripwire where you want it to be. 






## Requirements
- `stego_hunt.py` — Python 3, **Pillow** + **numpy** (`pip install pillow numpy` / `apt install python3-pil python3-numpy`)
- `triptrap.py` — Python 3, standard library only

## Commands

### stego_hunt.py — image canaries
```bash
# Interactive (prompts for image, name, destination, token):
python3 stego_hunt.py

# One-shot:
python3 stego_hunt.py plant --image <source_image> --name <new_name> \
    --dest <destination_dir> --token "<canary_token>"

# Keep the original instead of deleting it:
python3 stego_hunt.py plant ... --keep-original

# Recover a token from an image:
python3 stego_hunt.py extract <image>
```

### triptrap.py — any-file canaries
```bash
# Interactive:
python3 triptrap.py

# One-shot:
python3 triptrap.py plant --file <source_file> --name <new_name> \
    --dest <destination_dir> --token "<canary_token>"

# Keep the original:
python3 triptrap.py plant ... --keep-original

# Recover a token from a file:
python3 triptrap.py extract <file>
```

## Flags
| Flag | Meaning |
|------|---------|
| `--image` / `--file` | source you're turning into a canary |
| `--name` | new filename for the canary |
| `--dest` | directory where the canary will live |
| `--token` | your canary token (e.g. a canarytokens.org URL, or any unique marker) |
| `--keep-original` | do **not** delete the source (default: original is securely deleted) |

> Hidden token = **attribution** (trace a leaked copy via `extract`). For an alert
> when the file is *opened*, use a real **canarytokens.org callback token**.
