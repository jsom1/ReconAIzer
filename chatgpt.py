import openai

def get_exploitation_tips(service, version, client):
    """Sends service information to ChatGPT and retrieves exploitation tips."""
    prompt = (
        f"Service: {service}\n"
        f"Version: {version}\n"
        "Give exploitation tips for the discovered service, in the context of cybersecurity"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a penetration testing expert. Your role is to assist a newcomer in the field"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error trying to retrieve exploitation tips: {str(e)}"

