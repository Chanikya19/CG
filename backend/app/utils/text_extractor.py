import os
from io import BytesIO
import docx
import pypdf

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit
MAX_EXTRACT_CHARS = 1_000_000     # Maximum characters to extract (approx. 1MB of text)

def extract_text_from_txt(file_bytes):
    """
    Decodes plain text file bytes using UTF-8 or Latin-1 fallback with character limit safeguards.
    """
    try:
        # Enforce characters limit by truncating bytes first (estimating ~1 byte/char)
        safe_bytes = file_bytes[:MAX_EXTRACT_CHARS * 2]
        decoded = safe_bytes.decode('utf-8')
    except UnicodeDecodeError:
        decoded = safe_bytes.decode('latin-1', errors='ignore')
    
    return decoded[:MAX_EXTRACT_CHARS]

def extract_text_from_docx(file_bytes):
    """
    Extracts text from paragraphs and tables inside a DOCX file with character limit safeguards.
    """
    try:
        doc = docx.Document(BytesIO(file_bytes))
        full_text = []
        char_count = 0
        
        # Extract from paragraphs
        for para in doc.paragraphs:
            if para.text:
                full_text.append(para.text)
                char_count += len(para.text)
                if char_count > MAX_EXTRACT_CHARS:
                    break
        
        # Extract from tables if below threshold
        if char_count <= MAX_EXTRACT_CHARS:
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            full_text.append(cell.text)
                            char_count += len(cell.text)
                            if char_count > MAX_EXTRACT_CHARS:
                                break
                    if char_count > MAX_EXTRACT_CHARS:
                        break
                if char_count > MAX_EXTRACT_CHARS:
                    break
                    
        return "\n".join(full_text)[:MAX_EXTRACT_CHARS]
    except Exception as e:
        raise ValueError(f"Failed to extract text from DOCX file: The document is corrupted or unreadable. Detail: {str(e)}")

def extract_text_from_pdf(file_bytes):
    """
    Extracts text page-by-page from a PDF file using pypdf with character limit safeguards.
    """
    try:
        reader = pypdf.PdfReader(BytesIO(file_bytes))
        if reader.is_encrypted:
            raise ValueError("The PDF document is encrypted or password-protected.")
        
        full_text = []
        char_count = 0
        for page in reader.pages:
            text = page.extract_text()
            if text:
                full_text.append(text)
                char_count += len(text)
                if char_count > MAX_EXTRACT_CHARS:
                    break
        return "\n".join(full_text)[:MAX_EXTRACT_CHARS]
    except ValueError as ve:
        raise ve
    except Exception as e:
        raise ValueError(f"Failed to extract text from PDF file: The document is corrupted or unreadable. Detail: {str(e)}")

def extract_text(filename, file_bytes):
    """
    Identifies file extension, validates file size and format, and extracts text payload.
    Throws ValueError for unsupported formats, size violations, corruption, or empty content.
    """
    if not filename or not filename.strip():
        raise ValueError("Filename is required for text extraction")
        
    if file_bytes is None or len(file_bytes) == 0:
        raise ValueError("Document contains no readable text or is empty")

    # Enforce maximum file size limit
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"File size exceeds the maximum limit of 10MB (Size: {len(file_bytes) / (1024 * 1024):.2f}MB)")

    _, ext = os.path.splitext(filename.lower())
    if ext == '.txt':
        text = extract_text_from_txt(file_bytes)
    elif ext == '.docx':
        text = extract_text_from_docx(file_bytes)
    elif ext == '.pdf':
        text = extract_text_from_pdf(file_bytes)
    else:
        raise ValueError(f"Unsupported file format '{ext}'. Only PDF, DOCX, and TXT are supported.")

    # Enforce empty / whitespace only content validation
    if not text.strip():
        raise ValueError("Document contains no readable text or is empty")

    return text


