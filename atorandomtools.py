from colorama import Fore
import requests
import socket
import base64
import os
import re
import subprocess
import dns.resolver
import string

print(Fore.RED + """
            \       /
              .---.
         '-.  |   |  .-'
           ___|   |___
      -=  [           ]  =-
          `---.   .---'
       __||__ |   | __||__
       '-..-' |   | '-..-'
         ||   |   |   ||
         ||_.-|   |-,_||
       .-"`   `"`'`   `"-.
     .'                   '.
--------------------------------
""")

print("ig: ato.asd            discord: lailaheillalah")
print("[I] Welcome to random tools!")
print("[I] İf you get (None) requests api is broken contact me on social or u entered invalid.")
print("[I] Only for educational purposes..")
print(" ")
print("- [0] Exit")
print("- [1]  IP Address Lookup      ||    [11] Website Validator              ||    [21] Base32 Encode         ||    [31] Base82 Decode       ||    [41] BIN Checker")
print("- [2]  URL Shortener          ||    [12] Ping                           ||    [22] Base32 Decode         ||    [32] Base52 Encode       ||    [42] Proxy Checker")
print("- [3]  Base64 Encode          ||    [13] WHOIS Lookup                   ||    [23] Tilki.Dev AI          ||    [33] Base52 Decode       ||    [43] IPv6 Lookup")
print("- [4]  Base64 Decode          ||    [14] HTTP Header Checker            ||    [24] Gemini AI             ||    [34] MAC Adress Lookup   ||    [44] URL Shortener 2")
print("- [5]  Find File              ||    [15] SSL Certificate Checker        ||    [25] Password Generator    ||    [35] Morse Code Decode")
print("- [6]  Find Path              ||    [16] Network Scanner (Ping Sweep)   ||    [26] Discord ID Checker    ||    [36] Morse Code Encode")
print("- [7]  Port Checker           ||    [17] Hash Generator                 ||    [27] NPM İnformation       ||    [37] ChatGPT 4")
print("- [8]  Malware Scanner        ||    [18] Password Strength Checker      ||    [28] Roblox User Checker   ||    [38] Link Bypass")
print("- [9]  Subdomain Finder       ||    [19] Github User Checker            ||    [29] İmage Generator AI    ||    [39] Pastebin Creator")
print("- [10] DNS Lookup             ||    [20] Random User Generator          ||    [30] Base82 Encode         ||    [40] İndex Stealer")
print(" ")

def port_scanner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port} is open on {host}.")
        else:
            print(f"Port {port} is closed on {host}.")
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

def network_scanner(target):
    base_ip = ".".join(target.split(".")[:-1])  
    for i in range(1, 255):  
        ip = f"{base_ip}.{i}"
        try:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Host {ip} is up.")
        except Exception as e:
            print(f"Host {ip} is down or unreachable.")

def github_user_info(nickname):
    try:
        response = requests.get(f"https://api.popcat.xyz/github/{nickname}")
        response.raise_for_status()
        data = response.json()

        print("----------------------------")
        print(f"GitHub User Info for {nickname}:")
        print(f"URL: {data.get('url')}")
        print(f"Avatar: {data.get('avatar')}")
        print(f"Account Type: {data.get('account_type')}")
        print(f"Name: {data.get('name')}")
        print(f"Company: {data.get('company')}")
        print(f"Blog: {data.get('blog')}")
        print(f"Location: {data.get('location')}")
        print(f"Email: {data.get('email')}")
        print(f"Bio: {data.get('bio')}")
        print(f"Twitter: {data.get('twitter')}")
        print(f"Public Repos: {data.get('public_repos')}")
        print(f"Public Gists: {data.get('public_gists')}")
        print(f"Followers: {data.get('followers')}")
        print(f"Following: {data.get('following')}")
        print(f"Created At: {data.get('created_at')}")
        print(f"Updated At: {data.get('updated_at')}")
        print("----------------------------")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching GitHub user info: {e}")

def random_user_generator():
    try:
        response = requests.get("https://randomuser.me/api/")
        response.raise_for_status()
        data = response.json()
        user = data["results"][0]

        print("----------------------------")
        print("Random User Info:")
        print(f"Gender: {user['gender']}")
        print(f"Name: {user['name']['title']} {user['name']['first']} {user['name']['last']}")
        print(f"Location: {user['location']['street']['number']} {user['location']['street']['name']}, {user['location']['city']}, {user['location']['state']}, {user['location']['country']}")
        print(f"Email: {user['email']}")
        print(f"Phone: {user['phone']}")
        print(f"Cell: {user['cell']}")
        print(f"Picture: {user['picture']['large']}")
        print("----------------------------")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching random user data: {e}")

def base32_encode(text):
    try:
        encoded = base64.b32encode(text.encode()).decode()
        with open("base32encoded.txt", "w") as f:
            f.write(encoded)
        print("----------------------------")
        print(f"Text encoded and saved in 'base32encoded.txt'.")
        print("----------------------------")
    except Exception as e:
        print(f"Error encoding text: {e}")

def base32_decode(text):
    try:
        decoded = base64.b32decode(text).decode()
        with open("base32decoded.txt", "w") as f:
            f.write(decoded)
        print("----------------------------")
        print(f"Base32 decoded text saved to 'base32decoded.txt'.")
        print("----------------------------")
    except Exception as e:
        print(f"Error decoding text: {e}")

while True:
    choice = input("- Enter your choice: ")
    print(" ")

    if choice == "1":
        try:
            ip = input("- Enter an IP Address: ")
            data = requests.get(f"https://ipinfo.io/{ip}/json")
            data.raise_for_status()
            data = data.json()

            print("----------------------------")
            print("- IP Address: ", data.get("ip"))
            print("- Hostname: ", data.get("hostname"))
            print("- City: ", data.get("city"))
            print("- Region: ", data.get("region"))
            print("- Country: ", data.get("country"))
            print("- Location: ", data.get("loc"))
            print("- ORG: ", data.get("org"))
            print("- Postal: ", data.get("postal"))
            print("- Timezone: ", data.get("timezone"))
            print("----------------------------")

        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP data: {e}")
    
    elif choice == "2":
        try:
            link = input("- Enter the link you want to shorten: ")
            response = requests.get(f"http://tinyurl.com/api-create.php?url={link}")
            response.raise_for_status()
            link = response.text

            print("----------------------------")
            print("The URL we got shorten with TinyURL: ", link)
            print("----------------------------")

        except requests.exceptions.RequestException as e:
            print(f"Error shortening URL: {e}")

    elif choice == "3":
        text_to_encode = input("- Enter the text to encode in Base64: ")
        encoded = base64.b64encode(text_to_encode.encode()).decode()

        with open("base64encoded.txt", "w") as f:
            f.write(encoded)

        print("----------------------------")
        print(f"Text encoded and saved in 'base64encoded.txt'.")
        print("----------------------------")

    elif choice == "4":
        with open("base64encoded.txt", "r") as f:
            encoded_text = f.read()

        decoded = base64.b64decode(encoded_text).decode()

        with open("decoded_text.txt", "w") as f:
            f.write(decoded)

        print("----------------------------")
        print(f"Base64 decoded text saved to 'decoded_text.txt'.")
        print("----------------------------")

    elif choice == "5":
        filename = input("- Enter the filename to search for: ")
        if os.path.exists(filename):
            print("----------------------------")
            print(f"File {filename} found!")
            print(f"File Size: {os.path.getsize(filename)} bytes")
            print(f"File Path: {os.path.abspath(filename)}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("File not found.")
            print("----------------------------")
    
    elif choice == "6":
        file_path = input("- Enter the file path: ")
        if os.path.exists(file_path):
            print("----------------------------")
            print(f"Path exists: {file_path}")
            print(f"Is Directory: {os.path.isdir(file_path)}")
            print(f"Is File: {os.path.isfile(file_path)}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("Path not found.")
            print("----------------------------")
    
    elif choice == "7":
        host = input("- Enter the host to check port: ")
        port = int(input("- Enter the port number: "))
        port_scanner(host, port)
    
    elif choice == "8":
        file_path = input("- Enter the file path to scan for malware: ")

        if os.path.exists(file_path):
            print("----------------------------")
            print("Scanning file for potential malware...")
            try:
                with open(file_path, 'rb') as file:
                    content = file.read()
                    
                    if b"eval(" in content or b"exec(" in content:
                        print("Possible malware detected based on suspicious code.")
                    else:
                        print("No obvious malware signatures found.")
            except Exception as e:
                print(f"Error scanning the file: {e}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("File not found.")
            print("----------------------------")
    
    elif choice == "9":
        subdomain = input("- Enter the domain to find subdomains: ")
        response = requests.get(f"https://crt.sh/?q={subdomain}")
        print("----------------------------")
        print(f"Subdomains for {subdomain}:")
        print(response.text)
        print("----------------------------")

    elif choice == "10":
        domain = input("- Enter the domain to lookup DNS: ")
        try:
            answers = dns.resolver.resolve(domain, 'A')
            print("----------------------------")
            print(f"DNS lookup result for {domain}:")
            for rdata in answers:
                print(f"IP: {rdata.address}")
            print("----------------------------")
        except Exception as e:
            print(f"Error during DNS lookup: {e}")

    elif choice == "11":
        url = input("- Enter the website URL to validate: ")

        
        url_pattern = re.compile(r"^(https?://)?(www\.)?([a-zA-Z0-9-]+)\.([a-zA-Z]{2,6})(/[a-zA-Z0-9#]+/?)*$")
        
        if re.match(url_pattern, url):
            print("----------------------------")
            print(f"Valid URL format: {url}")
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(f"Website is accessible. Status Code: {response.status_code}")
                else:
                    print(f"Website is not accessible. Status Code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error while connecting to the website: {e}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("Invalid URL format.")
            print("----------------------------")
    
    elif choice == "12":
        ip = input("- Enter the IP address to ping: ")
        print(f"Pinging {ip} 10 times...")

        
        try:
            result = subprocess.run(["ping", "-c", "10", ip], capture_output=True, text=True)
            print("----------------------------")
            print(result.stdout)
            print("----------------------------")
        except Exception as e:
            print("----------------------------")
            print(f"Error pinging IP: {e}")
            print("----------------------------")
    
    elif choice == "13":
        domain = input("- Enter the domain for WHOIS lookup: ")
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True)
            print("----------------------------")
            print(result.stdout)
            print("----------------------------")
        except Exception as e:
            print("----------------------------")
            print(f"Error performing WHOIS lookup: {e}")
            print("----------------------------")
    
    elif choice == "14":
        url = input("- Enter the URL to check HTTP headers: ")
        try:
            response = requests.get(url)
            print("----------------------------")
            print("HTTP Headers:")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
            print("----------------------------")
        except requests.exceptions.RequestException as e:
            print("----------------------------")
            print(f"Error fetching HTTP headers: {e}")
            print("----------------------------")
    
    elif choice == "15":
        domain = input("- Enter the domain to check SSL certificate: ")
        try:
            result = subprocess.run(["openssl", "s_client", "-connect", f"{domain}:443"], capture_output=True, text=True)
            print("----------------------------")
            print(result.stdout)
            print("----------------------------")
        except Exception as e:
            print("----------------------------")
            print(f"Error checking SSL certificate: {e}")
            print("----------------------------")
    
    elif choice == "16":
        target = input("- Enter the target IP range (e.g., 192.168.1.0/24): ")
        network_scanner(target)
    
    elif choice == "17":
        text_to_hash = input("- Enter the text to generate hash: ")
        hash_type = input("- Enter the hash type (md5, sha1, sha256): ")
        if hash_type == "md5":
            import hashlib
            hash_object = hashlib.md5(text_to_hash.encode())
            print("----------------------------")
            print(f"MD5 Hash: {hash_object.hexdigest()}")
            print("----------------------------")
        elif hash_type == "sha1":
            import hashlib
            hash_object = hashlib.sha1(text_to_hash.encode())
            print("----------------------------")
            print(f"SHA1 Hash: {hash_object.hexdigest()}")
            print("----------------------------")
        elif hash_type == "sha256":
            import hashlib
            hash_object = hashlib.sha256(text_to_hash.encode())
            print("----------------------------")
            print(f"SHA256 Hash: {hash_object.hexdigest()}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("Invalid hash type.")
            print("----------------------------")
    
    elif choice == "18":
        password = input("- Enter the password to check strength: ")
        strength = 0
        if len(password) >= 8:
            strength += 1
        if re.search(r"[A-Z]", password):
            strength += 1
        if re.search(r"[a-z]", password):
            strength += 1
        if re.search(r"[0-9]", password):
            strength += 1
        if re.search(r"[!@#$%^&*()]", password):
            strength += 1
        
        print("----------------------------")
        if strength == 5:
            print("Password is very strong.")
        elif strength >= 3:
            print("Password is strong.")
        else:
            print("Password is weak.")
        print("----------------------------")
    
    elif choice == "19":
        nickname = input("- Enter the GitHub username: ")
        github_user_info(nickname)
    
    elif choice == "20":
        random_user_generator()
    
    elif choice == "21":
        text_to_encode = input("- Enter the text to encode in Base32: ")
        base32_encode(text_to_encode)
    
    elif choice == "22":
        text_to_decode = input("- Enter the text to decode in Base32: ")
        base32_decode(text_to_decode)
        
    elif choice == "23":
    	message = input("- Enter an message to Tilki.Dev AI: ")
    	
    	apiurl2 = f"https://tilki.dev/api/sohbet?soru={message}"
    	
    	response = requests.get(apiurl2)
    	datanew = response.json()
    	
    	print("----------------------------")
    	print("- You:", message)
    	print("- Tilki Dev AI:", datanew.get("cevap"))
    	print("----------------------------")
    	
    elif choice == "24":
    	message2 = input("- Enter an message to Gemini AI: ")
    	
    	apiurl3 = f"https://tilki.dev/api/hercai?soru={message2}"
    	
    	response = requests.get(apiurl3)
    	datanew2 = response.json()
    	
    	print("----------------------------")
    	print("- You:", message2)
    	print("- Gemini AI:", datanew2.get("cevap"))
    	print("----------------------------")
    	
    elif choice == "26":
    	id = input("- Enter an valid Discord ID: ")
    	
    	apiurl4 = f"https://tilki.dev/api/discord-id-sorgu/{id}"
    	
    	response = requests.get(apiurl4)
    	datanew3 = response.json()
    	
    	print("----------------------------")
    	print("- ID:", datanew3.get("id"))
    	print("- Username:", datanew3.get("username"))
    	print("- Discriminator:", datanew3.get("discriminator"))
    	print("- Avatar URL:", datanew3.get("avatarUrl"))
    	print("- Status:", datanew3.get("durum"))
    	print("- Status Text:", datanew3.get("durum_yazi"))
    	print("- Tag:", datanew3.get("tag"))
    	print("- Creation Date:", datanew3.get("olusturma_tarihi"))
    	print("- İs Bot?:", datanew3.get("botmu"))
    	print("----------------------------")
    	
    elif choice == "27":
    	npm = input("- Enter an NPM: ")
    	
    	apiurl5 = f"https://tilki.dev/api/npm-bilgi/{npm}"
    	
    	response = requests.get(apiurl5)
    	datanew4 = response.json()
    	
    	print("----------------------------")
    	print("- Name:", datanew4.get("name"))
    	print("- Link:", datanew4.get("link"))
    	print("- Latest Version:", datanew4.get("latestVersion"))
    	print("- Description", datanew4.get("description"))
    	print("- Repository:", datanew4.get("repository"))
    	print("- License:", datanew4.get("license"))
    	print("----------------------------")
    	
    elif choice == "28":
    	nickname = input("- Enter an valid Roblox username: ")
    	
    	apiurl6 = f"https://tilki.dev/api/roblox-kullanici-bilgi?ad={nickname}"
    	
    	response = requests.get(apiurl6)
    	datanew5 = response.json()
    	
    	print("----------------------------")
    	print("- Username:", datanew5.get("ad"))
    	print("- Display Name:", datanew5.get("gorunen_ad"))
    	print("- ID:", datanew5.get("id"))
    	print("- Description:", datanew5.get("description"))
    	print("- Creation Date:", datanew5.get("hesap_olusturma_tarihi"))
    	print("- İs Banned?:", datanew5.get("banlimi"))
    	print("- İs Verified?:", datanew5.get("onaylimi"))
    	print("- Character:", datanew5.get("karakter"))
    	print("- Profile Link:", datanew5.get("profil_link"))
    	print("----------------------------")
    	
    elif choice == "29":
    	prompt = input("- Enter an prompt for image (can be slow): ")
    	
    	apiurl7 = f"https://tilki.dev/api/imagine?q={prompt}"
    	
    	response = requests.get(apiurl7)
    	datanew6 = response.json()
    	
    	print("----------------------------")
    	print("- İmage Link: ", datanew6.get("url"))
    	print("----------------------------")
    	
    elif choice == "30":
        text = input("- Enter text to encode Base82: ")
        A = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[{]};:',<.>/?"

        def base82(d):
            if not d:
                return ""
            if isinstance(d, bytes):
                d = int.from_bytes(d, 'big')
            return base82(d // 82) + A[d % 82] if d else ""

        with open("base82_encode.txt", "w") as f:
            f.write(base82(text.encode())) 
        print("----------------------------")
        print("- Base82 encode saved to 'base82_encode.txt'")
        print("----------------------------")
        
    elif choice == "31":
        encoded_text = input("- Enter Base82 encoded text to decode: ")
        A = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[{]};:',<.>/?"

        def base82_decode(encoded):
            num = 0
            for char in encoded:
                num = num * 82 + A.index(char)
            byte_length = (num.bit_length() + 7) // 8
            return num.to_bytes(byte_length, 'big')

        decoded_text = base82_decode(encoded_text)
        
        with open("decoded_text.txt", "wb") as f:
            f.write(decoded_text)

        print("----------------------------")
        print("- Base82 decoded text saved to 'decoded_text.txt'")
        print("----------------------------")
        
    elif choice == "32":
        base52_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        text = input("- Enter text to encode Base52: ")
        encoded_text = "".join(base52_alphabet[ord(char) % 52] for char in text)

        with open("base52_encode.txt", "w") as f:
            f.write(encoded_text)

        print("----------------------------")
        print("- Base52 encode saved to 'base52_encode.txt'")
        print("----------------------------")
        
    elif choice == "33":
        base52_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        text = input("Enter Base52 encoded text: ")
        decoded_text = "".join(chr(base52_alphabet.index(char)) for char in text)

        with open("base52_decode.txt", "w") as f:
            f.write(decoded_text)

        print("----------------------------")
        print("- Base52 decode saved to 'base52_decode.txt'")
        print("----------------------------")
        
    elif choice == "34":
        mac = input("Enter MAC address: ")
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)

        if response.status_code == 200:
            print("----------------------------")
            print(f"- Vendor: {response.text}")
            print("----------------------------")
        else:
            print("----------------------------")
            print("- Invalid MAC address or not found.")
            print("----------------------------")
        
    elif choice == "35":
        morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9', '/': ' '
        }

        text = input("Enter text to Morse decode: ")
        decoded_text = "".join(morse_dict.get(char, '') for char in text.split())

        with open("morse_decode.txt", "w") as f:
            f.write(decoded_text)

        print("----------------------------")
        print("- Morse code decoded and saved to 'morse_decode.txt'")
        print("----------------------------")
    
    elif choice == "36":
        morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',  
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',  
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',  
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',  
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',  
        'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',  
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',  
        '9': '----.', ' ': '/'  
        }
        
        text = input("Enter text to encode in Morse code: ").upper()
        encoded_text = " ".join(morse_dict.get(char, '') for char in text)

        with open("morse_encode.txt", "w") as f:
            f.write(encoded_text)

        print("----------------------------")
        print("- Morse code encoded and saved to 'morse_encode.txt'")
        print("----------------------------")
        
    elif choice == "37":
    	msg = input("- Enter message for ChatGPT: ")
    	
    	apiurl8 = f"http://fi4.bot-hosting.net:22869/TestHubChatgptV4?msg={msg}&key=TestHub-ekbBiqAk9grpdBfMduJlTpMu"
    	
    	response = requests.get(apiurl8)
    	data = response.json()
    	
    	print("----------------------------")
    	print("- You:", msg)
    	print("- ChatGPT 4:", data.get("chat"))
    	print("----------------------------")
    	
    elif choice == "38":
    	link = input("- Enter an link for bypass (like linkvertise..): ")
    	
    	url = f"http://fi4.bot-hosting.net:22869/bypass?url={link}&key=TestHub-ekbBiqAk9grpdBfMduJlTpMu"
    	
    	response = requests.get(url)
    	data = response.json()
    	
    	print("----------------------------")
    	print("- The bypassed link we got: ", data.get("result"))
    	print("- Time:", data.get("elapsed_time"))
    	print("----------------------------")
    	
    elif choice == "39":
    	paste = input("- Enter text for paste to Pastebin: ")
    	
    	url = f"http://fi4.bot-hosting.net:22869/create_pastebin?content={paste}&key=TestHub-ekbBiqAk9grpdBfMduJlTpMu"
    	
    	response = requests.get(url)
    	data = response.json()
    	
    	print("----------------------------")
    	print("-", data.get("message"))
    	print("- The paste url: ", data.get("paste_url"))
    	print("----------------------------")
    	
    elif choice == "40":
         url = input("- Enter URL of site (with https://): ")     
         response = requests.get(url)
         response.raise_for_status()  
         with open("index.txt", "w", encoding="utf-8") as file:
             file.write(response.text)
         print("----------------------------")
         print("- İndex of site saved to index.txt.")
         print("----------------------------")
         
    elif choice == "41":
    	print("Example BIN: '426690'")
    	bin = input("- Enter valid BIN: ")
    	
    	url = f"https://api.dlyar-dev.tk/info-bin/?bin={bin}"
    	
    	response = requests.get(url)
    	data = response.json()
    	
    	print("----------------------------")
    	print("- Status:", data.get("status"))
    	print("- BIN:", data.get("bin")) 
    	print("- Country Code:", data.get("ccode"))
    	print("- Country:", data.get("country"))
    	print("- Country Flag:", data.get("flag"))
    	print("- Scheme:", data.get("scheme"))
    	print("- BIN Type:", data.get("type"))
    	print("- Brand:", data.get("brand"))
    	print("- Bank:", data.get("bank"))
    	print("- Currency:", data.get("currency"))
    	print("----------------------------")
    	
    elif choice == "42":
    	print("Example proxy: '72.221.232.155:4145'")
    	proxy = input("- Enter a Proxy to check: ")
    	
    	url = f"https://api.dlyar-dev.tk/cproxy/?p={proxy}"
    	
    	response = requests.get(url)
    	data = response.json()
    	
    	print("----------------------------")
    	print("- Status:", data.get("status"))
    	print("- Working:", data.get("working"))
    	print("----------------------------")
    	
    elif choice == "43":
    	 print("Example IPv6: '2001:4860:4860::8888'")
    	 ip = input("- Enter an IPv6 adress for check: ")
    	  	
    	 url = f"https://api.dlyar-dev.tk/whois/?ip={ip}"
    	  	
    	 response = requests.get(url)
    	 data = response.json()
    	     	  	
    	 print("----------------------------")
    	 print("- IPv6:", data.get("IP"))
    	 print("- Country:", data.get("country"))
    	 print("- Country-AR:", data.get("country-ar"))
    	 print("- Code:", data.get("code"))
    	 print("- Country Flag:", data.get("flag"))
    	 print("- ASN:", data.get("asn"))
    	 print("- ORG:", data.get("org"))
    	 print("- Code-Country:", data.get("code-country"))
    	 print("- Code-Country 2:", data.get("code-country2"))
    	 print("- Capital:", data.get("capital"))
    	 print("- City:", data.get("city"))
    	 print("- ZIP:", data.get("zip"))
    	 print("- Continent:", data.get("continent"))
    	 print("- Time-Zone:", data.get("time-zone"))
    	 print("- Time:", data.get("time"))
    	 print("- Date:", data.get("date"))
    	 print("- Currency:", data.get("currency"))
    	 print("- Language-Codes:", data.get("language-codes"))
    	 print("- Language:", data.get("language"))
    	 print("- Language2:", data.get("language2"))
    	 print("- Check-VPN:", data.get("check-vpn"))
    	 print("- IP Type:", data.get("type-ip"))
    	 print("----------------------------")
    	 
    elif choice == "44":
    	 link = input("- Enter link for URL Shorten 2 (is.gd): ")
    	 
    	 url = f"https://is.gd/create.php?format=simple&url={link}"
    	 
    	 response = requests.get(url)
    	 
    	 print("----------------------------")
    	 print("- The Shorten URL we got: ", response.text)
    	 print("----------------------------")
    	  	
    elif choice == "0":
         print("----------------------------")
         print("Exiting the program...")
         print("----------------------------")
         break

    else:
        print("----------------------------")
        print("Invalid option, please try again.")
        print("----------------------------")
