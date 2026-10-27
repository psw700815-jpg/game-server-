using System;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace BattleArena
{
    /// <summary>
    /// TCP 패킷 송수신 담당
    ///
    /// 패킷 형식 : [ 본문길이(4바이트) ][ JSON 본문 ]
    ///
    /// 길이를 앞에 붙이는 이유는 TCP가 경계를 보장하지 않기 때문입니다.
    /// </summary>
    public static class PacketHelper
    {
        /// <summary>한 패킷의 본문 최대 크기</summary>
        private const int MAX_BODY = 8192;

        // ═══════════════════════════════════════
        // 전송
        // ═══════════════════════════════════════
        public static async Task SendAsync(Socket socket, object packet)
        {
            string json = JsonConvert.SerializeObject(packet);
            byte[] body = Encoding.UTF8.GetBytes(json);

            byte[] full = new byte[4 + body.Length];
            BitConverter.GetBytes(body.Length).CopyTo(full, 0);
            body.CopyTo(full, 4);

            int sent = 0;
            while (sent < full.Length)
            {
                sent += await socket.SendAsync(
                    new ArraySegment<byte>(full, sent, full.Length - sent),
                    SocketFlags.None);
            }
        }

        // ═══════════════════════════════════════
        // 수신
        // ═══════════════════════════════════════
        public static async Task<string?> ReceiveAsync(Socket socket)
        {
            // 먼저 헤더 4바이트를 끝까지 읽어 본문 길이를 알아냅니다.
            // await ReceiveAsync 는 기다리는 동안 쓰레드를 반납합니다.
            byte[]? header = await ReceiveExactAsync(socket, 4);
            if (header == null) return null;          // 상대가 연결을 닫음

            int bodyLength = BitConverter.ToInt32(header, 0);

            // 말도 안 되는 길이가 오면 끊습니다 (악성 패킷 방어)
            if (bodyLength <= 0 || bodyLength > MAX_BODY) return null;

            // 알아낸 길이만큼 본문을 끝까지 읽습니다.
            byte[]? body = await ReceiveExactAsync(socket, bodyLength);
            if (body == null) return null;

            return Encoding.UTF8.GetString(body, 0, bodyLength);
        }

        /// <summary>
        /// 정확히 count 바이트를 받을 때까지 반복합니다.
        /// TCP는 경계가 없어서 요청한 만큼 한 번에 다 오지 않을 수 있습니다.
        /// </summary>
        private static async Task<byte[]?> ReceiveExactAsync(Socket socket, int count)
        {
            byte[] buffer = new byte[count];
            int received = 0;

            while (received < count)
            {
                int n = await socket.ReceiveAsync(
                    new ArraySegment<byte>(buffer, received, count - received),
                    SocketFlags.None);

                if (n == 0) return null;              // 상대가 연결을 닫음
                received += n;
            }

            return buffer;
        }
    }
}
