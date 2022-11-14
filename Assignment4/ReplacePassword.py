from cryptography.hazmat.primitives import hashes
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise Exception("Usage: python ReplacePassword.py <Group9.program2> <DesiredPassword>")
    group9program = sys.argv[1]

    digest = hashes.Hash(hashes.SHA1())
    digest.update(sys.argv[2].encode('utf-8'))
    passwordHash = digest.finalize()

    with open(group9program, 'r+b') as exe:
        exe.seek(0x1d3f6)
        exe.write(passwordHash)



