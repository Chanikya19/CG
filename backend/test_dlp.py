import unittest
from io import BytesIO
import os
import sys
from unittest.mock import MagicMock, patch

# Add app path to sys.path to resolve imports when running standalone
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.utils.text_extractor import extract_text
from app.AI.predict import classify_document, detect_security_indicators

class TestCipherGuardDLP(unittest.TestCase):

    def setUp(self):
        pass

    def test_extract_text_txt(self):
        content = "This is a normal public announcement. Our company is dedicated to open communication."
        file_bytes = content.encode('utf-8')
        extracted = extract_text("announcement.txt", file_bytes)
        self.assertEqual(extracted.strip(), content)

    def test_extract_text_docx(self):
        import docx
        doc = docx.Document()
        doc.add_paragraph("Internal department guidelines. Do not share outside.")
        f = BytesIO()
        doc.save(f)
        docx_bytes = f.getvalue()

        extracted = extract_text("guidelines.docx", docx_bytes)
        self.assertEqual(extracted.strip(), "Internal department guidelines. Do not share outside.")

    @patch('pypdf.PdfReader')
    def test_extract_text_pdf(self, mock_pdf_reader):
        # Mock page content extraction
        mock_page = MagicMock()
        mock_page.extract_text.return_value = "Sensitive financial audit reports."
        
        mock_reader_inst = MagicMock()
        mock_reader_inst.is_encrypted = False
        mock_reader_inst.pages = [mock_page]
        mock_pdf_reader.return_value = mock_reader_inst

        pdf_bytes = b"%PDF-1.4 mock content"
        extracted = extract_text("audit.pdf", pdf_bytes)
        self.assertEqual(extracted.strip(), "Sensitive financial audit reports.")

    @patch('pypdf.PdfReader')
    def test_encrypted_pdf_error(self, mock_pdf_reader):
        mock_reader_inst = MagicMock()
        mock_reader_inst.is_encrypted = True
        mock_pdf_reader.return_value = mock_reader_inst

        pdf_bytes = b"%PDF-1.4 encrypted content"
        with self.assertRaises(ValueError) as ctx:
            extract_text("encrypted.pdf", pdf_bytes)
        self.assertIn("encrypted or password-protected", str(ctx.exception))

    def test_empty_file_error(self):
        with self.assertRaises(ValueError) as ctx:
            extract_text("empty.txt", b"")
        self.assertIn("no readable text or is empty", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            extract_text("whitespace.txt", b"     \n\t   ")
        self.assertIn("no readable text or is empty", str(ctx.exception))

    def test_unsupported_file_error(self):
        with self.assertRaises(ValueError) as ctx:
            extract_text("malicious.exe", b"binary executable payload")
        self.assertIn("Unsupported file format", str(ctx.exception))

    def test_very_large_file_error(self):
        large_bytes = b"A" * (10 * 1024 * 1024 + 10)  # slightly larger than 10MB
        with self.assertRaises(ValueError) as ctx:
            extract_text("huge.txt", large_bytes)
        self.assertIn("exceeds the maximum limit", str(ctx.exception))

    def test_indicator_detection(self):
        # 1. Credentials
        indicators1 = detect_security_indicators("DATABASE_URL=mysql://admin:pass@localhost:3306")
        self.assertIn("Credentials", indicators1)

        # 2. SSN
        indicators2 = detect_security_indicators("SSN 123-45-6789 list of employees")
        self.assertIn("Government identifiers", indicators2)
        self.assertIn("Personal information", indicators2)

        # 3. Account numbers
        indicators3 = detect_security_indicators("routing number 123456789 and bank account number 99882211")
        self.assertIn("Account numbers", indicators3)

        # 4. Financial info
        indicators4 = detect_security_indicators("Credit Card transaction record 4111-2222-3333-4444")
        self.assertIn("Financial information", indicators4)

        # 5. Confidential keywords
        indicators5 = detect_security_indicators("This contains trade secret information restricted distribution.")
        self.assertIn("Confidential keywords", indicators5)

    def test_transparent_classification_public(self):
        text = "This is a general public press release welcoming everyone to our website."
        result = classify_document(text)
        self.assertEqual(result["category"], "PUBLIC")
        self.assertFalse(result["override_applied"])
        self.assertIn("No sensitive rule-based indicators", result["explanation"])

    def test_transparent_classification_secret_override(self):
        # ML predicts public or confidential, but credentials trigger SECRET override
        text = "Check our public webpage at http://example.com and remember password=mysecret!"
        result = classify_document(text)
        self.assertEqual(result["category"], "SECRET")
        self.assertTrue(result["override_applied"])
        self.assertIn("Credentials", result["detected_indicators"])
        self.assertIn("triggered a safety override", result["explanation"])

    def test_transparent_classification_confidential_override(self):
        text = "Welcome to the public catalog of open source templates. Restricted internal use only."
        result = classify_document(text)
        self.assertEqual(result["category"], "CONFIDENTIAL")
        self.assertTrue(result["override_applied"])
        self.assertIn("Confidential keywords", result["detected_indicators"])
        self.assertIn("triggered a safety override", result["explanation"])

if __name__ == '__main__':
    unittest.main()
