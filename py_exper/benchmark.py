import asyncio
import aiohttp
import time
import json
import random
import sys

URL = "http://127.0.0.1:7000/upload"
LENGTH = 1001

if len(sys.argv) > 1:
    try:
        LENGTH = int(sys.argv[1])
    except ValueError:
        print("데이터 수를 입력해주세요. 기본값 1000으로 시작합니다.")
        LENGTH = 1001
else:
    LENGTH = 1001

async def send_one(i):
    # 100~200 사이의 목표 바이트 설정
    target_size = random.randint(100, 200)

    # 필수값만 포함한 최소 체급 페이로드 생성
    # info의 cCode와 clinic_id는 유지, 나머지는 최소화
    payload = [{
        "clinic_id": f"C{i:05d}",
        "info": {"cCode": f"A{i:05d}"},
        "patient_id": f"P{i:05d}",
        "presc_code": "",
        "ts": ""  # 길이를 고정
    }]
    # clinic_his는 omitempty이므로 None(null)으로 두면 전송 시 제외됨

    # 현재 사이즈 측정
    current_json = json.dumps(payload, separators=(',', ':'))
    current_size = len(current_json.encode('utf-8'))

    # 목표치(target_size)까지 presc_code에 패딩 추가
    # JSON 인코딩 시 발생하는 오버헤드를 고려하여 diff 계산
    diff = target_size - current_size
    if diff > 0:
        payload[0]["presc_code"] = "X" * diff

    # 최종 전송 데이터 확정 및 전송
    final_data = json.dumps(payload, separators=(',', ':'))
    actual_size = len(final_data.encode('utf-8'))

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(URL, data=final_data, headers={'Content-Type': 'application/json'},
                                    timeout=10) as response:
                print(f"[{i:05d}] Target: {target_size}B | Actual: {actual_size}B | Status: {response.status}")
    except Exception as e:
        print(f"Error at {i}: {e}")
        pass


async def main():
    global start_time
    print(f"========== 100~200B 정밀 타격 시작 ({LENGTH}건) ==========")
    start_time = time.time()
    for i in range(1, LENGTH):
        await send_one(i)
        await asyncio.sleep(0.001)
    print(f"========== 실험 완료: {time.time() - start_time:.2f}초 ==========")


if __name__ == "__main__":
    asyncio.run(main())

