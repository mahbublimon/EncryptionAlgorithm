def main(max_length_multiplier: float):
    assert max_length_multiplier > 0


    sample_strings = [
        "Hello, World!",
        "This is a sample string",
        "Another string for testing",
        "A very very long string that should result in a high score",
        "Short string",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "1234567890",
        "A string with special characters: !@#$%^&*()",
        "A string with spaces    between     words",
        "A string with a mix of letters, numbers, and special characters: abc123!@#"
    ]


    # Define the weights for each metric
    weights = {
        "unique_chars": 0.1,
        "distinct_sequences": 1.0,
        "entropy": 1.5,
        "frequency_analysis": 0.1,
        "length_consistency": 0.5,
        "evenness": 1.2,
        "reversibility": 2.0,
        "change_propagation": 1.5,
        "pattern_analysis": 1.5,
        "correlation_analysis": 1.5,
        "complexity": 1.0,
        "randomness": 1.5,
        "normalized_levenshtein": 1.0,
        "encryption_consistency": 2.0,  # High weight as this is critical
        "running_time": 0.5
    }


    print("\n********** RSA Cipher Testing **********")
    rsa_scores = []
    rsa_table_data = []

    for i, original_string in enumerate(sample_strings, start=1):
        cipher = Cipher(original_string)

        start_time = time.time()

        public_key, private_key = cipher.generate_keys()
        cipher.encrypt(public_key)

        end_time = time.time()
        running_time = end_time - start_time

        decrypted_string = cipher.decrypt(private_key)
        decryption_success = decrypted_string == original_string

        rsa_scores.append(decryption_success)
        rsa_table_data.append([
            i, original_string, cipher.encrypted_string,
            decrypted_string, decryption_success, running_time
        ])

    Scoring.print_rsa_results(rsa_table_data, rsa_scores)
    print("\n********** RSA Testing Complete **********\n")

if __name__ == "__main__":
    main(2.0)
