import os

from vectorguard.targets.openai_like import OpenAILikeTarget


def main() -> None:
    target = OpenAILikeTarget(
        base_url=os.environ["VG_BASE_URL"],
        api_key=os.environ["VG_API_KEY"],
        model=os.environ["VG_MODEL"],
    )

    result = target.send_prompt("Say hello in one sentence.")
    print("STATUS:", result.status_code)
    print("LATENCY_MS:", round(result.latency_ms, 2))
    print("TEXT:", result.text)


if __name__ == "__main__":
    main()