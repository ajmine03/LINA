from ollama import chat

print("\n=== Linux AI Assistant v0.2 ===")
print("Type 'exit' to quit.\n")

conversation = []

while True:
    user_input = input("You: ")

    if user_input.lower() == "exit":
        print("\nGoodbye!\n")
        break

    conversation.append({
        "role": "user",
        "content": user_input
    })

    stream = chat(
        model="qwen2.5:3b",
        messages=[
            {
                "role": "system",
                "content": "Reply briefly and clearly."
            }
        ] + conversation,
        stream=True
    )

    print("\nAssistant: ", end="", flush=True)

    full_reply = ""

    for chunk in stream:
        content = chunk["message"]["content"]
        full_reply += content

        print(content, end="", flush=True)

    print("\n")

    conversation.append({
        "role": "assistant",
        "content": full_reply
    })
