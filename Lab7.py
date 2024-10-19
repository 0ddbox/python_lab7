import string


def vigenere_sq():
    alphabet = string.ascii_uppercase
    print("   " + " ".join(alphabet))
    print("  +" + "-" * 51)
    square = [[index_to_letter((i + j) % 26, alphabet) for j in range(26)] for i in range(26)]
    for i, row in enumerate(square):
        print(f"{alphabet[i]} | {' '.join(row)}")


def letter_to_index(letter, alphabet):
    return alphabet.index(letter.upper())


def index_to_letter(index, alphabet):
    return alphabet[index % 26]


def vigenere_index(key_letter, plaintext_letter, alphabet):
    return index_to_letter(
        (letter_to_index(key_letter, alphabet) + letter_to_index(plaintext_letter, alphabet)) % 26,
        alphabet
    )


def encrypt_vigenere(key, plaintext, alphabet):
    key = key.upper()
    plaintext = plaintext.upper()
    key_length = len(key)
    ciphertext = []

    for i, letter in enumerate(plaintext):
        if letter in alphabet:
            key_letter = key[i % key_length]
            ciphertext.append(vigenere_index(key_letter, letter, alphabet))
        else:
            ciphertext.append(letter)

    return ''.join(ciphertext)


def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    return index_to_letter(
        (letter_to_index(cipher_letter, alphabet) - letter_to_index(key_letter, alphabet)) % 26,
        alphabet
    )


def decrypt_vigenere(key, ciphertext, alphabet):
    key = key.upper()
    ciphertext = ciphertext.upper()
    key_length = len(key)
    plaintext = []

    for i, letter in enumerate(ciphertext):
        if letter in alphabet:
            key_letter = key[i % key_length]
            plaintext.append(undo_vigenere_index(key_letter, letter, alphabet))
        else:
            plaintext.append(letter)

    return ''.join(plaintext)


def main():
    alphabet = string.ascii_uppercase
    encrypted_texts = []
    keys = []

    menu_options = [
        ("Encrypt", lambda: encrypt_option(alphabet, encrypted_texts, keys)),
        ("Decrypt", lambda: decrypt_option(alphabet, encrypted_texts, keys)),
        ("Dump Encrypted Text", lambda: dump_encrypted(encrypted_texts)),
        ("Print Vigenère Square", vigenere_sq),
        ("Add Key", lambda: add_key(keys)),
        ("Exit", lambda: print("Goodbye!"))
    ]

    while True:
        print("\nVigenère Cipher Menu:")
        for i, (option, _) in enumerate(menu_options, 1):
            print(f"{i}. {option}")

        choice = input("Enter your choice (1-6): ")

        try:
            choice = int(choice)
            if 1 <= choice <= len(menu_options):
                menu_options[choice - 1][1]()
                if choice == len(menu_options):  # Exit option
                    break
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def encrypt_option(alphabet, encrypted_texts, keys):
    if not keys:
        print("No keys available. Please add a key first.")
        return

    plaintext = input("Enter the plaintext: ")
    key = keys[len(encrypted_texts) % len(keys)]  # Rotate keys
    ciphertext = encrypt_vigenere(key, plaintext, alphabet)
    encrypted_texts.append(ciphertext)
    print(f"Encrypted text: {ciphertext}")
    print(f"Key used: {key}")


def decrypt_option(alphabet, encrypted_texts, keys):
    if not encrypted_texts:
        print("No encrypted texts available.")
        return
    if not keys:
        print("No keys available. Please add a key first.")
        return

    for i, ciphertext in enumerate(encrypted_texts):
        key = keys[i % len(keys)]
        plaintext = decrypt_vigenere(key, ciphertext, alphabet)
        print(f"Decrypted text {i + 1}: {plaintext}")
        print(f"Key used: {key}")


def dump_encrypted(encrypted_texts):
    if not encrypted_texts:
        print("No encrypted texts available.")
    else:
        for i, text in enumerate(encrypted_texts, 1):
            print(f"Encrypted text {i}: {text}")


def add_key(keys):
    new_key = input("Enter a new key: ").upper()
    if new_key.isalpha():
        keys.append(new_key)
        print(f"Key '{new_key}' added successfully.")
    else:
        print("Invalid key. Please use alphabetic characters only.")


if __name__ == "__main__":
    main()