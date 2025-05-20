import threading
import requests
from bs4 import BeautifulSoup
from queue import Queue
import pickle
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk
import time
import re
from urllib.parse import urlparse

stop_event = threading.Event()  # global event to stop threads

def save_state(visited, queue):
    with open("visited_urls.pkl", "wb") as f:
        pickle.dump(visited, f)
    with open("urls_to_visit.pkl", "wb") as f:
        pickle.dump(list(queue.queue), f)

def load_state():
    visited = set()
    queue = Queue()
    if os.path.exists("visited_urls.pkl"):
        with open("visited_urls.pkl", "rb") as f:
            visited = pickle.load(f)
    if os.path.exists("urls_to_visit.pkl"):
        with open("urls_to_visit.pkl", "rb") as f:
            for url in pickle.load(f):
                queue.put(url)
    return visited, queue

def crawl_worker(queue, visited, lock, result_text, progress_bar, num_threads, keyword, base_domain, status_label, blacklist):
    processed = 0
    while not queue.empty() and not stop_event.is_set():
        url = queue.get()

        with lock:
            if url in visited:
                queue.task_done()
                continue
            visited.add(url)

        try:
            response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code != 200:
                queue.task_done()
                continue

            soup = BeautifulSoup(response.text, 'html.parser')

            title = soup.title.string.strip() if soup.title else "No Title"

            if keyword.lower() in url.lower():
                with lock:
                    result_text.insert(tk.END, f"[{title}] {url}\n")
                    result_text.yview(tk.END)
                    processed += 1
                    progress_bar['value'] = (processed / num_threads) * 100
                    progress_bar.update()
                    status_label.config(text=f"Crawled: {len(visited)} pages")

            for link in soup.find_all('a', href=True):
                abs_url = requests.compat.urljoin(url, link['href'])

                parsed = urlparse(abs_url)
                if not abs_url.startswith("http"):
                    continue
                if not parsed.netloc.endswith(base_domain):
                    continue
                if any(abs_url.lower().endswith(ext) for ext in blacklist):
                    continue

                with lock:
                    if abs_url not in visited:
                        queue.put(abs_url)

        except requests.exceptions.RequestException:
            pass

        if len(visited) % 10 == 0:
            save_state(visited, queue)

        queue.task_done()

    with lock:
        result_text.insert(tk.END, "[✓] Crawling complete or stopped.\n")
        result_text.yview(tk.END)

def start_crawling(start_url, num_threads, result_text, progress_bar, keyword, status_label, blacklist):
    stop_event.clear()
    visited, url_queue = load_state()

    if url_queue.empty():
        if not re.match(r'^(http://|https://)', start_url):
            messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http:// or https://")
            return
        url_queue.put(start_url)

    base_domain = urlparse(start_url).netloc
    lock = threading.Lock()
    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(target=crawl_worker, args=(
            url_queue, visited, lock, result_text, progress_bar, num_threads,
            keyword, base_domain, status_label, blacklist))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    url_queue.join()

def stop_crawling():
    stop_event.set()

def export_results(visited):
    if visited:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                for url in visited:
                    f.write(url + "\n")
            messagebox.showinfo("Exported", f"URLs saved to {file_path}")
    else:
        messagebox.showwarning("Empty", "No URLs to export.")

def setup_ui():
    root = tk.Tk()
    root.title("🕸️ Web Crawler Pro")
    root.geometry("750x700")
    root.config(bg="#2e2e2e")

    root.option_add("*background", "#2e2e2e")
    root.option_add("*foreground", "#ffffff")
    root.option_add("*font", "Helvetica 12")

    tk.Label(root, text="Enter URL to Start Crawling:").pack(pady=5)
    url_entry = tk.Entry(root, width=70)
    url_entry.pack(pady=5)

    tk.Label(root, text="Keyword to Filter URLs:").pack(pady=5)
    keyword_entry = tk.Entry(root, width=50)
    keyword_entry.pack(pady=5)
    keyword_entry.insert(0, "")  # default: no filter

    result_text = scrolledtext.ScrolledText(root, width=90, height=25, wrap=tk.WORD)
    result_text.pack(pady=10)
    result_text.config(bg="#333333", fg="#ffffff", insertbackground="white")

    progress_bar = ttk.Progressbar(root, orient='horizontal', length=600, mode='determinate')
    progress_bar.pack(pady=5)

    status_label = tk.Label(root, text="Crawled: 0 pages", bg="#2e2e2e", fg="white")
    status_label.pack()

    def start_crawl():
        result_text.delete(1.0, tk.END)
        progress_bar['value'] = 0
        keyword = keyword_entry.get().strip()
        url = url_entry.get().strip()
        blacklist = ['.pdf', '.zip', '.jpg', '.png', '.mp4']
        threading.Thread(target=start_crawling, args=(url, 5, result_text, progress_bar, keyword, status_label, blacklist), daemon=True).start()

    def export():
        if os.path.exists("visited_urls.pkl"):
            with open("visited_urls.pkl", "rb") as f:
                visited = pickle.load(f)
            export_results(visited)
        else:
            messagebox.showwarning("Not Found", "No visited URL data available.")

    tk.Button(root, text="▶ Start Crawling", command=start_crawl, bg="#4CAF50").pack(pady=10)
    tk.Button(root, text="■ Stop Crawling", command=stop_crawling, bg="#e74c3c").pack(pady=5)
    tk.Button(root, text="💾 Export URLs", command=export, bg="#3498db").pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    setup_ui()
