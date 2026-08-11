import os
from io import BytesIO
import docx
import pypdf

def extract_text_from_txt(file_bytes):
    """
    Decodes plain text file bytes using UTF-8 or Latin-1 fallback.
    """
    try:
        return file_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return file_bytes.decode('latin-1', errors='ignore')

def extract_text_from_docx(file_bytes):
    """
    Extracts text from paragraphs and tables inside a DOCX file.
    """
    try:
        doc = docx.Document(BytesIO(file_bytes))
        full_text = []
        for para in doc.paragraphs:
            if para.text:
                full_text.append(para.text)
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text:
                        full_text.append(cell.text)
        return "\n".join(full_text)
    except Exception as e:
        raise ValueError(f"Failed to extract text from DOCX file: {str(e)}")

def extract_text_from_pdf(file_bytes):
    """
    Extracts text page-by-page from a PDF file using pypdf.
    """
    try:
        reader = pypdf.PdfReader(BytesIO(file_bytes))
        full_text = []
        for page in reader.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)
        return "\n".join(full_text)
    except Exception as e:
        raise ValueError(f"Failed to extract text from PDF file: {str(e)}")

def extract_text(filename, file_bytes):
    """
    Identifies file extension and routes to appropriate text extractor.
    Throws ValueError for unsupported formats.
    """
    if not filename:
        raise ValueError("Filename is required for text extraction")
        
    _, ext = os.path.splitext(filename.lower())
    if ext == '.txt':
        return extract_text_from_txt(file_bytes)
    elif ext == '.docx':
        return extract_text_from_docx(file_bytes)
    elif ext == '.pdf':
        return extract_text_from_pdf(file_bytes)
    else:
        raise ValueError(f"Unsupported file format '{ext}'. Only PDF, DOCX, and TXT are supported.")
