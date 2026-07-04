import requests

def dir_brute_force(url, wordlist):
    for dir in wordlist:
        full_url = f"{url}/{dir}"
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"Found this directory that might be useful: {full_url}")
        else:
            print(f"These did not return a 200: {full_url}")

url = input("Enter the base URL (e.g., http://hackers-rule.hack): ")
wordlist = ["admin", "images", "uploads", "files", "test", "private"]  # Customize this with your own list. But like before, I need to figure out a way to upload a file instead of a list like this.

dir_brute_force(url, wordlist)
