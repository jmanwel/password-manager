import argparse
import hashlib
import random
import string
import uuid


def createPassword(plain_text: str) -> str:
    CHARS = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(CHARS) for i in range(plain_text))


def findHash(hash: str, path_dict: str) -> str:
    "try to decrypt a hash using a dictionary"    
    with open(path_dict, "r") as file:
        dictionary = [ line.strip()  for line in file ]
        for password in dictionary:
            for method in [ "sha1", "sha256", "sha512", "md5", "sha3_512", "sha3_384", "shake128" ]:
                calculatedHash = hashPass(password, method)
                if calculatedHash == hash:
                    return password
            return "password not found"


def hashPass(passString: str, method: str) -> str:
    "hash a plain text string using a provided method"
    match method:
        case "sha256":
            return hashlib.sha256(passString.encode()).hexdigest()
        case "sha1":
            print("WARNING DEPRECATED METHOD!")
            return hashlib.sha1(passString.encode()).hexdigest()
        case "sha512":
            return hashlib.sha256(passString.encode()).hexdigest()
        case "md5":
            return hashlib.md5(passString.encode()).hexdigest()
        case "sha3_512":
            return hashlib.sha3_512(passString.encode()).hexdigest()
        case "sha3_384":
            return hashlib.sha3_384(passString.encode()).hexdigest()
        case "shake_128":
            return hashlib.shake_128(passString.encode()).hexdigest(15)
        case _:
            return "Method not supported"


def hashText(text: str) -> str:
    "Hash provided text + :salt"
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + text.encode()).hexdigest() + ':' + salt


def matchHashedText(hashedText: str, providedText: str) -> str:
    "Check if providedText match with hashedText"
    _hashedText, salt = hashedText.split(':')
    return _hashedText == hashlib.sha256(salt.encode() + providedText.encode()).hexdigest()


if __name__ == "__main__": 
    # HANDLE ARGUMENTS
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", "-a", type=str, help="Action to perform.")
    parser.add_argument("--password", "-pwd", type=str, help="Password.")
    parser.add_argument("--method", "-m", type=str, help="sha256, sha512, etc")
    parser.add_argument("--path", "-p", type=str, help="Path to dictionary")
    parser.add_argument("--hashed", "-ha", type=str, help="Hash to decode")
    args = parser.parse_args()

    if args.action == "create":
        print(createPassword(args.password))
    if args.action == "find":
        print(findHash(args.hashed, args.path))
    if args.action == "hash":
        print(hashPass(args.password, args.method))
    if args.action == "match":
        print(matchHashedText(args.password, args.hashed))
    if args.action == "hashsalt":
        print(hashText(args.password))