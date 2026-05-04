import hashlib
import os

# Secure Remote Password (SRP-6a) Protocol - Zero Knowledge Proof Demo
# This proves to a server you know the password without sending it over the network.

# A safe 2048-bit prime (N) and generator (g) from RFC 5054
N_hex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9CEFBEFD8CE359FB0A9EC3CDEEE02737F93373E0C10BA809AA4F2A145C8641C54C73B21"
N = int(N_hex, 16)
g = 2

def H(*args):
    """SHA-256 Hash of concatenated arguments."""
    ctx = hashlib.sha256()
    for a in args:
        if isinstance(a, int):
            ctx.update(str(a).encode('utf-8'))
        elif isinstance(a, bytes):
            ctx.update(a)
        else:
            ctx.update(str(a).encode('utf-8'))
    return int.from_bytes(ctx.digest(), 'big')

# Server multiplier
k = H(N, g)

class SRPServer:
    def __init__(self):
        self.db = {} # username -> (salt, verifier)
        self.sessions = {}
        
    def register(self, username, salt, verifier):
        self.db[username] = (salt, verifier)
        
    def step1(self, username, A):
        salt, v = self.db[username]
        b = int.from_bytes(os.urandom(32), 'big')
        B = (k * v + pow(g, b, N)) % N
        self.sessions[username] = (b, B, A, v)
        return salt, B
        
    def step2(self, username, M1):
        b, B, A, v = self.sessions[username]
        u = H(A, B)
        S = pow(A * pow(v, u, N), b, N)
        K = H(S)
        
        expected_M1 = H(A, B, K)
        if M1 == expected_M1:
            M2 = H(A, M1, K)
            return True, M2
        return False, None

class SRPClient:
    def __init__(self, username, password):
        self.I = username
        self.p = password
        
    def generate_registration(self):
        salt = os.urandom(16)
        x = H(salt, self.I, self.p)
        v = pow(g, x, N)
        return salt, v
        
    def login(self, server):
        a = int.from_bytes(os.urandom(32), 'big')
        A = pow(g, a, N)
        
        # Step 1: Send A to server
        salt, B = server.step1(self.I, A)
        
        # Calculate shared secret
        u = H(A, B)
        x = H(salt, self.I, self.p)
        S = pow(B - k * pow(g, x, N), a + u * x, N)
        K = H(S)
        
        # Prove we know K
        M1 = H(A, B, K)
        
        # Step 2: Send M1 to server
        success, M2 = server.step2(self.I, M1)
        
        if success:
            print("Client: Successfully authenticated without sending password!")
            expected_M2 = H(A, M1, K)
            if M2 == expected_M2:
                print("Client: Server is also verified (Mutual Authentication)!")
        else:
            print("Client: Authentication failed!")

if __name__ == "__main__":
    print("--- SRP Zero-Knowledge Proof Demo ---")
    server = SRPServer()
    client = SRPClient("admin", "supersecret123")
    
    # Registration Phase
    salt, v = client.generate_registration()
    server.register("admin", salt, v)
    print("Server has stored ONLY the Salt and Verifier (No Password).")
    
    # Login Phase
    client.login(server)
