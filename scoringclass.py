class Scoring:
    def __init__(self, cipher: 'Cipher', running_time: float, weights: Dict[str, float], max_length_multiplier: float = 2.0) -> None:
        self.cipher = cipher
        self.weights = weights
        self.max_length_multiplier = max_length_multiplier
        self.running_time = running_time
        self.frequency = Counter(self.cipher.encrypted_string)
        self.score = self.calculate_score()
        self.summary = self.generate_summary()

    def unique_chars_metric(self) -> float:
        return len(set(self.cipher.encrypted_string)) / len(set(string.printable))

    def distinct_sequences_metric(self) -> float:
        sequences = [''.join(seq) for seq in zip(self.cipher.encrypted_string, self.cipher.encrypted_string[1:])]
        return len(set(sequences)) / max(1, len(set(combinations(string.printable, 2))))

    def entropy_metric(self) -> float:
        probabilities = [count / len(self.cipher.encrypted_string) for count in self.frequency.values()]
        return scipy_entropy(probabilities, base=2) / math.log2(len(set(string.printable)))

    def frequency_analysis_metric(self) -> float:
        most_common_char_frequency = self.frequency.most_common(1)[0][1] / len(self.cipher.encrypted_string)
        return 1 - most_common_char_frequency

    def length_consistency_metric(self) -> float:
        return abs(len(self.cipher.encrypted_string) - len(self.cipher.original_string)) / len(self.cipher.original_string)

    def evenness_metric(self) -> float:
        frequencies = list(self.frequency.values())
        mean_freq = sum(frequencies) / len(frequencies)
        variance = sum((freq - mean_freq) ** 2 for freq in frequencies) / len(frequencies)
        return 1 - (math.sqrt(variance) / len(self.cipher.encrypted_string))

    def reversibility_metric(self) -> float:
        decrypted_string = self.cipher.decrypt()
        return float(decrypted_string == self.cipher.original_string)

    def change_propagation_metric(self) -> float:
        changed_string = 'a' + self.cipher.original_string[1:]
        cipher_changed = Cipher(changed_string)
        cipher_changed.encrypt()
        changed_encrypted_string = cipher_changed.encrypted_string
        levenshtein_distance = self._levenshtein_distance(self.cipher.encrypted_string, changed_encrypted_string)
        return levenshtein_distance / len(self.cipher.encrypted_string)

    def pattern_analysis_metric(self) -> float:
        pattern_instances_orig = sum(1 for a, b in zip(self.cipher.original_string, self.cipher.original_string[1:]) if a == b)
        pattern_instances_enc = sum(1 for a, b in zip(self.cipher.encrypted_string, self.cipher.encrypted_string[1:]) if a == b)

        if pattern_instances_orig == 0:
            return 1.0  # No repeated patterns in the original string
        elif pattern_instances_enc == 0:
            return 1.0  # No repeated patterns in the encrypted string
        else:
            return 1 - (pattern_instances_enc / pattern_instances_orig)


    def correlation_analysis_metric(self) -> float:
        correlations = sum(1 for a, b in zip(self.cipher.original_string, self.cipher.encrypted_string) if a == b)
        correlation_metric = correlations / len(self.cipher.original_string)
        return 1 - correlation_metric

    def complexity_metric(self) -> float:
        return len(self.cipher.encrypted_string) / len(self.cipher.original_string)

    def randomness_metric(self) -> float:
        random_string = ''.join(random.choice(string.printable) for _ in range(len(self.cipher.original_string)))
        cipher = Cipher(random_string)
        cipher.encrypt()
        random_encrypted_string = cipher.encrypted_string
        random_encrypted_frequency = Counter(random_encrypted_string)
        frequencies = list(random_encrypted_frequency.values())
        mean_freq = sum(frequencies) / len(frequencies)
        variance = sum((freq - mean_freq) ** 2 for freq in frequencies) / len(frequencies)
        return math.sqrt(variance) / len(string.printable)

    def normalized_levenshtein_metric(self) -> float:
        decrypted_string = self.cipher.decrypt()
        distance = self._levenshtein_distance(self.cipher.original_string, decrypted_string)
        return 1 - distance / max(len(self.cipher.original_string), len(decrypted_string))

    def encryption_consistency_metric(self) -> float:
        original_string = self.cipher.original_string
        original_encrypted_string = self.cipher.encrypted_string
        self.cipher.original_string = original_string
        self.cipher.encrypted_string = ""
        self.cipher.encrypt()
        second_encryption = self.cipher.encrypted_string
        self.cipher.encrypted_string = original_encrypted_string

        return float(original_encrypted_string == second_encryption)

    def running_time_metric(self) -> float:
        return np.clip(1 - self.running_time, 0, 1)


    def calculate_score(self) -> float:
        total_score = 0
        try:
            if len(self.cipher.encrypted_string) > len(self.cipher.original_string) * self.max_length_multiplier:
                raise Exception("The length of the encrypted string exceeds the allowed limit. This entry is disqualified.")

            total_score += self.weights["unique_chars"] * self.unique_chars_metric()
            total_score += self.weights["distinct_sequences"] * self.distinct_sequences_metric()
            total_score += self.weights["entropy"] * self.entropy_metric()
            total_score += self.weights["frequency_analysis"] * self.frequency_analysis_metric()
            total_score += self.weights["length_consistency"] * self.length_consistency_metric()
            total_score += self.weights["evenness"] * self.evenness_metric()
            total_score += self.weights["reversibility"] * self.reversibility_metric()
            total_score += self.weights["change_propagation"] * self.change_propagation_metric()
            total_score += self.weights["pattern_analysis"] * self.pattern_analysis_metric()
            total_score += self.weights["correlation_analysis"] * self.correlation_analysis_metric()
            total_score += self.weights["complexity"] * self.complexity_metric()
            total_score += self.weights["randomness"] * self.randomness_metric()
            total_score += self.weights["normalized_levenshtein"] * self.normalized_levenshtein_metric()
            total_score += self.weights["encryption_consistency"] * self.encryption_consistency_metric()
            total_score += self.weights["running_time"] * self.running_time_metric()
        except Exception as e:
            print(f"An error occurred while calculating the score: {e}")
            return 0

        return total_score

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        # len(s1) >= len(s2)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]


    def generate_summary(self) -> Dict[str, float]:
        summary = {
            "unique_chars": self.unique_chars_metric(),
            "distinct_sequences": self.distinct_sequences_metric(),
            "entropy": self.entropy_metric(),
            "frequency_analysis": self.frequency_analysis_metric(),
            "length_consistency": self.length_consistency_metric(),
            "evenness": self.evenness_metric(),
            "reversibility": self.reversibility_metric(),
            "change_propagation": self.change_propagation_metric(),
            "pattern_analysis": self.pattern_analysis_metric(),
            "correlation_analysis": self.correlation_analysis_metric(),
            "complexity": self.complexity_metric(),
            "randomness": self.randomness_metric(),
            "normalized_levenshtein": self.normalized_levenshtein_metric(),
            "encryption_consistency": self.encryption_consistency_metric(),
            "running_time": self.running_time_metric()  # New metric
        }
        return summary


    @staticmethod
    def print_rsa_results(table_data: List[List[str]], scores: List[bool]) -> None:
        try:
            table = PrettyTable()
            table.field_names = ["Test No.", "Original String", "Encrypted String",
                                 "Decrypted String", "Decryption Success", "Running Time"]

            for data in table_data:
                table.add_row(data)

            print(table)
            print(f"\nAverage score: {sum(scores) / len(scores)}")
        except Exception as e:
            print(f"An error occurred while printing the results: {e}")
