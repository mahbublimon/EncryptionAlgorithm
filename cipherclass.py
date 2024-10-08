class Cipher:

    def __init__(self, original_string: str) -> None:
        self.original_string = original_string
        self.encrypted_string = ""

    def generate_keys(self):
        p = sympy.randprime(2**64, 2**128)
        q = sympy.randprime(2**64, 2**128)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = sympy.randprime(3, phi - 1)
        d = sympy.mod_inverse(e, phi)

        return (e, n), (d, n)


    def encrypt(self, public_key):
        e, n = public_key
        encrypted_data = [pow(ord(char), e, n) for char in self.original_string]
        self.encrypted_string = ' '.join(map(str, encrypted_data))

    def decrypt(self, private_key):
        d, n = private_key
        encrypted_data = self.encrypted_string.split()
        decrypted_data = [chr(pow(int(char), d, n)) for char in encrypted_data]
        return ''.join(decrypted_data)
