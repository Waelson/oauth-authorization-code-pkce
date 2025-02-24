import { useState, useEffect } from "react";

const clientId = "1084790336194-a71dqkqnl92kq3lqai48p1dbda8haus7.apps.googleusercontent.com";
const authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
const tokenEndpoint = "http://localhost:4000/token";
const redirectUri = "http://localhost:3000/callback";
const backendApi = "http://localhost:4000/protected";
const scope = "openid email profile";
const state = crypto.randomUUID();

const generateCodeVerifier = () => {
  const array = new Uint8Array(32);
  window.crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
};

const sha256 = async (plain) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
};

export default function App() {
  const [codeVerifier, setCodeVerifier] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");

    const storedVerifier = sessionStorage.getItem("codeVerifier");

    if (code && storedVerifier) {
      setCodeVerifier(storedVerifier);
      exchangeCodeForToken(code);
    }
  }, []);

  const authorize = async () => {
    const verifier = generateCodeVerifier();
    sessionStorage.setItem("codeVerifier", verifier);
    setCodeVerifier(verifier);
    const challenge = await sha256(verifier);

    const url = `${authorizationEndpoint}?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${encodeURIComponent(
        scope
    )}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256&access_type=offline&include_granted_scopes=true&prompt=consent`;

    window.location.href = url;
  };

  const exchangeCodeForToken = async (code) => {
    setError(""); // Limpa erros anteriores
    try {
      const storedVerifier = sessionStorage.getItem("codeVerifier");

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          code_verifier: storedVerifier,
        }),
      });

      if (!response.ok) {
        throw new Error("Falha ao obter o token de acesso.");
      }

      const data = await response.json();
      setAccessToken(data.access_token);
    } catch (error) {
      setError("Erro ao autenticar. Tente novamente.");
    }
  };

  const fetchData = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(backendApi, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        throw new Error("Falha ao buscar dados protegidos.");
      }

      const data = await response.json();
      setData(data);
    } catch (error) {
      setError("Erro ao carregar os dados protegidos.");
    } finally {
      setLoading(false);
    }
  };

  return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gray-100 p-6">
        <div className="bg-white shadow-lg rounded-lg p-8 w-full max-w-md text-center">
          <h1 className="text-2xl font-bold text-gray-800 mb-6">OAuth2 com PKCE</h1>

          {error && (
              <div className="mb-4 p-3 bg-red-100 text-red-600 rounded-md">
                ⚠️ {error}
              </div>
          )}

          {!accessToken ? (
              <button
                  onClick={authorize}
                  className="w-full flex items-center justify-center py-3 px-4 bg-white border border-gray-300 shadow-md rounded-lg text-gray-700 font-medium hover:bg-gray-200 transition duration-200"
              >
                  <img src="https://img.icons8.com/color/24/google-logo.png" alt="Google Logo" className="mr-3"/>
                  Login com Google
              </button>
          ) : (
              <div>
                  <button
                      onClick={fetchData}
                    className="w-full py-3 px-4 bg-green-600 text-white rounded-lg hover:bg-green-700 transition duration-200"
                >
                  📡 Buscar Dados Protegidos
                </button>

                {loading && (
                    <div className="mt-4 text-gray-600">
                      <span className="animate-spin inline-block mr-2">⏳</span>
                      Carregando...
                    </div>
                )}

                {data && (
                    <pre className="mt-4 p-3 bg-gray-200 rounded-lg text-left text-sm text-gray-800 overflow-x-auto">
                {JSON.stringify(data, null, 2)}
              </pre>
                )}
              </div>
          )}
        </div>
      </div>
  );
}
