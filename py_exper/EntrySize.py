import json
import random


def simulate_fixed_sizes(count=1000):
    print(f"{'Index':^8} | {'Target':^8} | {'Actual':^8} | {'Diff':^5}")
    print("-" * 45)

    size_history = []

    for i in range(1, count + 1):
        target_size = random.randint(100, 200)

        payload = [{
            "clinic_id": f"C{i:05d}",
            "info": {"cCode": f"L{i:05d}"},
            "patient_id": f"P{i:05d}",
            "presc_code": "",
            "ts": ""  # 길이를 고정
        }]

        # 현재 사이즈 측정
        current_data = json.dumps(payload, separators=(',', ':'))  # 공백 제거 옵션 추가
        current_size = len(current_data.encode('utf-8'))

        # 3. 모자란 만큼 채웁니다.
        diff = target_size - current_size
        if diff > 0:
            payload[0]["presc_code"] = "X" * diff

        # 4. [최종 검증] 다시 인코딩해서 사이즈 확인
        final_data = json.dumps(payload, separators=(',', ':'))
        actual_bytes = len(final_data.encode('utf-8'))

        # 만약 딱 안 맞으면(JSON 구조상 차이 발생 시) 미세 조정
        if actual_bytes > target_size:
            over = actual_bytes - target_size
            payload[0]["presc_code"] = payload[0]["presc_code"][:-over]
            final_data = json.dumps(payload, separators=(',', ':'))
            actual_bytes = len(final_data.encode('utf-8'))

        size_history.append(actual_bytes)
        print(f"{i:8d} | {target_size:7d}B | {actual_bytes:7d}B | {actual_bytes - target_size:5d}")

    print("-" * 45)
    print(f"평균: {sum(size_history) / len(size_history):.2f}B | 최소: {min(size_history)}B | 최대: {max(size_history)}B")


if __name__ == "__main__":
    simulate_fixed_sizes(1000)