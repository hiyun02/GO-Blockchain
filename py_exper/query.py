import asyncio
import aiohttp
import time
import random
import sys

# 설정값
BASE_URL = "http://127.0.0.1:5000/query"
TOTAL_REQUESTS = 101  # 100건 테스트를 위해 101로 설정
SLEEP_MIN = 0.1
SLEEP_MAX = 5.0

# 매개변수 처리
if len(sys.argv) > 1:
    try:
        MAX_KEYWORD = int(sys.argv[1])
    except ValueError:
        print("숫자를 입력해주세요. 기본값 1001로 시작합니다.")
        MAX_KEYWORD = 1001
else:
    MAX_KEYWORD = 1001


async def run_query(i, hos_id, log_file):
    # hos_id에 맞춰 키워드 접두사를 결정하고 초(s) 단위로 레이턴시 측정
    rand_num = random.randint(1, MAX_KEYWORD)
    prefix = hos_id[-1]
    keyword = f"{prefix}{rand_num:05d}"

    params = {
        "hos_id": hos_id,
        "keyword": keyword
    }

    start = time.time()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(BASE_URL, params=params, timeout=5) as response:
                status = response.status
                await response.read()
    except Exception as e:
        status = f"ERROR:{str(e)}"

    end = time.time()

    # 초 단위로 계산
    elapsed_s = round(end - start, 3)

    # 출력 및 기록 형식 변경
    log_line = f"{i} | {keyword} | {elapsed_s} | {status}"
    print(f"[{hos_id}] [{i}] {keyword} | {elapsed_s} s | {status}")

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_line + "\n")


async def main():
    hospitals = ["Hos-A", "Hos-B"]

    for hos_id in hospitals:
        # 파일명에 병원 이름을 포함시켜야 데이터가 덮어씌워지지 않습니다.
        current_log = f"query-16-{MAX_KEYWORD - 1}-{hos_id}.txt"

        with open(current_log, "w", encoding="utf-8") as f:
            f.write(f"--- Test for {hos_id} ---\n")
            f.write("index | keyword | latency(sec) | status \n")  # 헤더명 변경
            f.write("-----------------------------------------------------\n")

        print(f"\n========== {hos_id} 쿼리 테스트 시작 ({TOTAL_REQUESTS - 1}건) ==========")

        for i in range(1, TOTAL_REQUESTS):
            await run_query(i, hos_id, current_log)
            wait_time = random.uniform(SLEEP_MIN, SLEEP_MAX)
            await asyncio.sleep(wait_time)

        print(f"========== {hos_id} 테스트 완료 ==========")


if __name__ == "__main__":
    asyncio.run(main())