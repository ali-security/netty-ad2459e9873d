/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.channel.kqueue;

import io.netty.channel.unix.DomainSocketAddress;
import io.netty.channel.unix.FileDescriptor;
import io.netty.channel.unix.tests.UnixTestUtils;
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Verifies that {@code recvFd} never leaks file descriptors when the peer sends more than one descriptor in a
 * single {@code SCM_RIGHTS} message.
 * <p>
 * The JDK and Netty can only send a single descriptor per message, so the malicious peer is a small python3 script.
 * It sends the write ends of freshly created pipes and closes its own copies. A pipe's read end only observes EOF
 * once every copy of its write end has been closed, so EOF on all pipes proves the receiver closed (or never
 * installed) every descriptor it was sent.
 */
public class KQueueDomainSocketMultipleFdsTest {

    private static final String PYTHON = "python3";

    private static final String PEER_SCRIPT =
            "import array, os, select, socket, sys\n" +
            "path = sys.argv[1]\n" +
            "count = int(sys.argv[2])\n" +
            "pipes = [os.pipe() for _ in range(count)]\n" +
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n" +
            "s.connect(path)\n" +
            "fds = array.array('i', [w for (r, w) in pipes])\n" +
            "s.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])\n" +
            "for (r, w) in pipes:\n" +
            "    os.close(w)\n" +
            "sys.stdout.write('SENT\\n')\n" +
            "sys.stdout.flush()\n" +
            "sys.stdin.readline()\n" +
            "leaked = []\n" +
            "for i in range(count):\n" +
            "    r = pipes[i][0]\n" +
            "    if not select.select([r], [], [], 5)[0] or os.read(r, 1) != b'':\n" +
            "        leaked.append(i)\n" +
            "s.close()\n" +
            "sys.stdout.write('LEAKED %s\\n' % leaked)\n" +
            "sys.stdout.flush()\n";

    @BeforeAll
    public static void loadJNI() {
        KQueue.ensureAvailability();
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    public void testSingleFdIsReceived() throws Exception {
        PeerResult result = sendFdsAndReceive(1);
        assertTrue(result.received > 0, "a single descriptor must still be received, recvFd() returned " +
                result.received + " / " + result.error);
        assertEquals("LEAKED []", result.leaked);
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    public void testTwoFdsAreClosed() throws Exception {
        assertAllFdsClosedAndRejected(sendFdsAndReceive(2));
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    public void testManyFdsAreClosed() throws Exception {
        assertAllFdsClosedAndRejected(sendFdsAndReceive(8));
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    public void testMaximumFdsAreClosed() throws Exception {
        // Close to the largest SCM_RIGHTS message the kernel accepts (SCM_MAX_FD is 253 on Linux, XNU accepts 254).
        assertAllFdsClosedAndRejected(sendFdsAndReceive(250));
    }

    private static void assertAllFdsClosedAndRejected(PeerResult result) {
        assertEquals("LEAKED []", result.leaked, "descriptors sent by the peer were leaked (recvFd() returned " +
                result.received + " / " + result.error + ')');
        assertNotNull(result.error, "recvFd() must fail when the peer sends more than one descriptor, but returned " +
                result.received);
    }

    private static PeerResult sendFdsAndReceive(int count) throws Exception {
        assumeTrue(isPythonAvailable(), PYTHON + " is required to send multiple file descriptors in one message");

        DomainSocketAddress address = UnixTestUtils.newDomainSocketAddress();
        BsdSocket server = BsdSocket.newSocketDomain();
        BsdSocket accepted = null;
        Process peer = null;
        try {
            server.bind(address);
            server.listen(1);

            peer = new ProcessBuilder(PYTHON, "-c", PEER_SCRIPT, address.path(), String.valueOf(count))
                    .redirectErrorStream(true).start();
            BufferedReader peerOut = new BufferedReader(
                    new InputStreamReader(peer.getInputStream(), CharsetUtil.US_ASCII));
            readLine(peerOut, "SENT");

            int acceptedFd = server.accept(new byte[64]);
            assertTrue(acceptedFd > 0, "peer connection was not accepted");
            accepted = new BsdSocket(acceptedFd);

            PeerResult result = new PeerResult();
            try {
                result.received = accepted.recvFd();
                if (result.received > 0) {
                    new FileDescriptor(result.received).close();
                }
            } catch (IOException e) {
                result.error = e;
            }

            // Tell the peer we are done so it checks which of its pipes are still held open by this process.
            OutputStream peerIn = peer.getOutputStream();
            peerIn.write('\n');
            peerIn.flush();
            result.leaked = readLine(peerOut, "LEAKED");
            assertEquals(0, peer.waitFor());
            return result;
        } finally {
            if (accepted != null) {
                accepted.close();
            }
            server.close();
            if (peer != null) {
                peer.destroy();
            }
        }
    }

    private static String readLine(BufferedReader reader, String prefix) throws IOException {
        StringBuilder output = new StringBuilder();
        for (;;) {
            String line = reader.readLine();
            if (line == null) {
                fail("peer exited before printing '" + prefix + "', output: " + output);
            }
            if (line.startsWith(prefix)) {
                return line;
            }
            output.append(line).append('\n');
        }
    }

    private static boolean isPythonAvailable() {
        try {
            Process process = new ProcessBuilder(PYTHON, "-c", "import array, select, socket; socket.SCM_RIGHTS")
                    .redirectErrorStream(true).start();
            return process.waitFor() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static final class PeerResult {
        int received;
        IOException error;
        String leaked;
    }
}
