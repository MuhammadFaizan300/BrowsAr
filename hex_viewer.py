import sys

def simple_hex_viewer(file_path, bytes_per_line=16):
    try:
        with open(file_path, 'rb') as f: # 'rb' means Read Binary
            address = 0
            while True:
                chunk = f.read(bytes_per_line)
                if not chunk:
                    break
                
                # Create the Hexadecimal part
                hex_part = ' '.join(f"{b:02x}" for b in chunk)
                
                # Create the Readable Text part (replace non-readable characters with a dot)
                text_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                
                # Print the Address, Hex, and Text
                print(f"{address:08x}  {hex_part:<48}  |{text_part}|")
                address += bytes_per_line
                
                # Stop after a certain point for testing (e.g., first 512 bytes)
                if address >= 512:
                    print("\n--- Showing first 512 bytes for demonstration ---")
                    break
                    
    except FileNotFoundError:
        print("Error: File not found.")

# Testing it on a system file (e.g., a simple text file you create)
if __name__ == "__main__":
    # Create a dummy file to test
    with open("test.txt", "w") as test:
        test.write("Hello FAST NUCES! This is a forensics test.")
    
    print("Testing Hex Viewer on test.txt:\n")
    simple_hex_viewer("test.txt")