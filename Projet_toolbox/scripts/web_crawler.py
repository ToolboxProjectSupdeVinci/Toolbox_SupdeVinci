import requests
from bs4 import BeautifulSoup
import urllib.parse

def request(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers)
        return response.text
    except requests.RequestException as e:
        print(f"Error: {e}")
        return None

def get_links(html, base_url):
    internal_links = set()
    external_links = set()
    images = set()
    css_files = set()
    js_files = set()

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("a", href=True):
        link = urllib.parse.urljoin(base_url, tag['href'])
        if base_url in link:
            internal_links.add(link)
        else:
            external_links.add(link)

    for tag in soup.find_all("img", src=True):
        src = urllib.parse.urljoin(base_url, tag['src'])
        images.add(src)

    for tag in soup.find_all("link", href=True):
        if tag['href'].endswith(".css"):
            href = urllib.parse.urljoin(base_url, tag['href'])
            css_files.add(href)

    for tag in soup.find_all("script", src=True):
        if tag['src'].endswith(".js"):
            src = urllib.parse.urljoin(base_url, tag['src'])
            js_files.add(src)

    return internal_links, external_links, images, css_files, js_files

def crawl(url, max_pages=5):
    to_crawl = [url]
    crawled = set()
    report = {
        "internal_links": set(),
        "external_links": set(),
        "images": set(),
        "css_files": set(),
        "js_files": set()
    }

    while to_crawl and len(crawled) < max_pages:
        current_url = to_crawl.pop(0)
        if current_url not in crawled:
            html = request(current_url)
            if html:
                internal_links, external_links, images, css_files, js_files = get_links(html, url)
                report["internal_links"].update(internal_links)
                report["external_links"].update(external_links)
                report["images"].update(images)
                report["css_files"].update(css_files)
                report["js_files"].update(js_files)

                to_crawl.extend(internal_links - crawled)
                crawled.add(current_url)
                print(f"Crawled: {current_url}")

    return report

if __name__ == "__main__":
    url = "http://books.toscrape.com"
    report = crawl(url)
    print(f"Internal Links: {report['internal_links']}")
    print(f"External Links: {report['external_links']}")
    print(f"Images: {report['images']}")
    print(f"CSS Files: {report['css_files']}")
    print(f"JavaScript Files: {report['js_files']}")
