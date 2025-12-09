import json
import requests

API_KEY = "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"  # ضع مفتاح Groq هنا
API_URL = "https://api.groq.com/openai/v1/chat/completions"

def ask_groq(user_input):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a smart assistant that processes reports or files based on user instructions."},
            {"role": "user", "content": user_input}
        ]
    }
    resp = requests.post(API_URL, headers=headers, json=data)
    resp.raise_for_status()
    res = resp.json()
    return res["choices"][0]["message"]["content"]

if __name__ == "__main__":
    # اختيار نوع الملف
    file_path = input("Enter the file name (TXT or JSON): ")

    if file_path.lower().endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            file_content = json.load(f)
        # تحويل JSON لنص منسق
        file_text = json.dumps(file_content, indent=4)
    else:  # TXT أو أي ملف نصي
        with open(file_path, "r", encoding="utf-8") as f:
            file_text = f.read()

    # طلب المهمة من المستخدم
    task = input("What do you want the AI to do with this file? ")

    # تجهيز prompt للنموذج
    prompt = f"""
Here is the file content:
{file_text}

Task: {task}
Please provide a clear response in English.
"""

    result = ask_groq(prompt)
    print("\nAI Result:\n", result)
