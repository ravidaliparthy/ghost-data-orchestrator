"""
Unit tests for IntentClassifier.
Covers:
- Multilingual deletion requests (en, es, fr, de, pt, it, nl, tr, ru, ja, zh, ko, hi, ar)
- Negation detection within token window
- Non-deletion requests (access, export, rectification, marketing opt-out, password reset)
- Hypothetical / questions
- Partial scope requests
- Mixed request precedence
"""
import unittest
import sys
import os

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from engine.intent_classifier import IntentClassifier

class TestIntentClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = IntentClassifier()

    def test_multilingual_deletion(self):
        cases = [
            ("Please permanently delete my account and all associated personal data.", "en", True),
            ("Por favor, eliminen mi cuenta y todos mis datos personales.", "es", True),
            ("Veuillez supprimer mon compte et effacer mes données personnelles.", "fr", True),
            ("Bitte löschen Sie mein Konto und alle personenbezogenen Daten.", "de", True),
            ("Solicito a exclusão permanente da minha conta e de todos os dados.", "pt", True),
            ("Per favore cancellate il mio account e tutti i miei dati.", "it", True),
            ("Gelieve mijn account en alle persoonsgegevens te verwijderen.", "nl", True),
            ("Lütfen hesabımı ve tüm kişisel verilerimi silin.", "tr", True),
            ("Пожалуйста, удалите мою учетную запись и все данные.", "ru", True),
            ("アカウントとすべての個人データを完全に削除してください。", "ja", True),
            ("请注销我的账户并删除所有相关的个人信息。", "zh", True),
            ("제 계정을 영구적으로 삭제하고 개인정보를 모두 파기해 주세요.", "ko", True),
            ("कृपया मेरा खाता और सभी व्यक्तिगत डेटा हमेशा के लिए हटा दें।", "hi", True),
            ("يرجى حذف حسابي ومسح جميع بياناتي الشخصية بشكل نهائي.", "ar", True),
        ]
        for text, lang, expected in cases:
            res = self.classifier.classify(text)
            self.assertEqual(res.authorized, expected, f"Failed for {lang}: '{text}' (res.authorized={res.authorized}, reasons={res.reasons})")

    def test_negation_near_deletion(self):
        negated_cases = [
            "Please do NOT delete my account. I want to keep it active.",
            "I do not want you to delete or close my profile.",
            "Ne supprimez pas mon compte s'il vous plaît.",
            "Bitte löschen Sie mein Konto nicht.",
            "Por favor, não exclua minha conta.",
            "Non cancellare il mio account.",
            "アカウントを削除しないでください。",
            "계정을 삭제하지 마세요.",
        ]
        for text in negated_cases:
            res = self.classifier.classify(text)
            self.assertFalse(res.authorized, f"Failed to detect negation in: '{text}' (res.authorized={res.authorized})")
            self.assertTrue(res.negation_detected or not res.authorized)

    def test_non_deletion_overrides(self):
        overrides = [
            "I want to request a copy of my personal data under GDPR access rights.",
            "Please export all my order history and transaction logs to a CSV.",
            "I need to rectify my birth date and update my registered phone number.",
            "Please unsubscribe me from all promotional and marketing emails.",
            "I forgot my password and cannot log into my account. Please assist.",
            "Por favor envíenme una copia de mis datos personales.",
            "Veuillez me désabonner de toutes les communications marketing.",
            "Auskunft über gespeicherte Daten anfordern.",
        ]
        for text in overrides:
            res = self.classifier.classify(text)
            self.assertFalse(res.authorized, f"Non-deletion falsely authorized: '{text}' (res.authorized={res.authorized})")

    def test_hypothetical_questions(self):
        questions = [
            "What happens if I delete my account? Can I restore it later?",
            "What if I decide to delete my data tomorrow?",
            "How do I close my account if I still have active credits?",
            "¿Qué sucede si elimino mi cuenta?",
            "Que se passe-t-il si je supprime mon compte ?",
        ]
        for text in questions:
            res = self.classifier.classify(text)
            self.assertFalse(res.authorized, f"Hypothetical question falsely authorized: '{text}' (res.authorized={res.authorized})")

    def test_partial_scope(self):
        partial = [
            "Please delete marketing data only, but keep my account active for purchases.",
            "Just remove me from the newsletter and promotional campaigns.",
            "Supprimez uniquement mes données marketing s'il vous plaît.",
        ]
        for text in partial:
            res = self.classifier.classify(text)
            self.assertFalse(res.authorized, f"Partial scope falsely authorized: '{text}' (res.authorized={res.authorized})")

    def test_mixed_preparatory_request(self):
        mixed = [
            "Please export a copy of my data and then permanently delete my account.",
            "Download my order history and then erase my profile.",
        ]
        for text in mixed:
            res = self.classifier.classify(text)
            self.assertTrue(res.authorized, f"Mixed preparatory request failed to authorize: '{text}' (res.authorized={res.authorized})")

if __name__ == "__main__":
    unittest.main()
