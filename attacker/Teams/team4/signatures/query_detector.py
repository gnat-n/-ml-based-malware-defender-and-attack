from detector import analyze_file
import sys

if __name__ == '__main__':
    file_name = sys.argv[1]
    detect, name = analyze_file(file_name)

    if detect == 1:
        print(f'Packer Detected: {name}')
    elif detect == 2:
        print(f'Cryptor Detected: {name}')
    elif detect == 0:
        print('All Clear')