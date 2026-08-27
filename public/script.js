const $ = (selector) => document.querySelector(selector);

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  let data = {};
  try {
    data = await response.json();
  } catch {
    data = { message: "Unexpected server response." };
  }

  return { response, data };
}

function showAlert(element, message, type = "error") {
  if (!element) return;
  element.textContent = message;
  element.classList.remove("hidden", "success");
  if (type === "success") element.classList.add("success");
}

function hide(element) {
  if (element) element.classList.add("hidden");
}

// ---------- Login ----------

const loginForm = $("#loginForm");

if (loginForm) {
  const loginCard = $("#loginCard");
  const otpCard = $("#otpCard");
  const alert = $("#alert");
  const otpAlert = $("#otpAlert");
  let loginChallengeId = null;

  $("#togglePassword").addEventListener("click", () => {
    const input = $("#password");
    const button = $("#togglePassword");
    input.type = input.type === "password" ? "text" : "password";
    button.textContent = input.type === "password" ? "Show" : "Hide";
  });

  $("#forgotPassword").addEventListener("click", () => {
    showAlert(alert, "Password recovery is represented by this UI in the demo. A production reset flow should use a separate verified recovery challenge.");
  });

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hide(alert);

    const email = $("#email").value.trim();
    const password = $("#password").value;
    const rememberMe = $("#rememberMe").checked;

    if (!email || !password) {
      showAlert(alert, "Please enter your email and password.");
      return;
    }

    $("#loginButton").disabled = true;
    $("#loginButton").textContent = "Checking...";

    try {
      const { response, data } = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({ email, password, rememberMe })
      });

      if (!response.ok) {
        showAlert(alert, data.message || "Login failed.");
        return;
      }

      loginChallengeId = data.challengeId;
      loginCard.classList.add("hidden");
      otpCard.classList.remove("hidden");
      $("#otp").focus();
    } catch {
      showAlert(alert, "Could not connect to the authentication server.");
    } finally {
      $("#loginButton").disabled = false;
      $("#loginButton").textContent = "Login";
    }
  });

  $("#otpForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    hide(otpAlert);

    const otp = $("#otp").value.trim();

    if (!/^\d{6}$/.test(otp)) {
      showAlert(otpAlert, "Enter the 6-digit OTP.");
      return;
    }

    $("#verifyButton").disabled = true;
    $("#verifyButton").textContent = "Verifying...";

    try {
      const { response, data } = await api("/api/verify-login-otp", {
        method: "POST",
        body: JSON.stringify({
          challengeId: loginChallengeId,
          otp
        })
      });

      if (!response.ok) {
        showAlert(
          otpAlert,
          data.attemptsRemaining
            ? `${data.message} Attempts remaining: ${data.attemptsRemaining}.`
            : data.message
        );

        if (data.locked) {
          $("#verifyButton").disabled = true;
        }
        return;
      }

      window.location.href = "/dashboard.html";
    } catch {
      showAlert(otpAlert, "Could not verify the OTP.");
    } finally {
      $("#verifyButton").disabled = false;
      $("#verifyButton").textContent = "Verify & continue";
    }
  });

  $("#backToLogin").addEventListener("click", () => {
    otpCard.classList.add("hidden");
    loginCard.classList.remove("hidden");
    $("#otp").value = "";
    hide(otpAlert);
  });

  $("#resendOtp").addEventListener("click", async () => {
    showAlert(otpAlert, "To get a new login OTP, return to login and submit your credentials again.", "success");
  });
}

// ---------- Registration ----------

const registerForm = $("#registerForm");

if (registerForm) {
  const registerCard = $("#registerCard");
  const emailOtpCard = $("#emailOtpCard");
  const smsOtpCard = $("#smsOtpCard");
  const successCard = $("#successCard");

  let registrationChallengeId = null;
  let registrationUserId = null;

  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hide($("#registerAlert"));

    const payload = {
      name: $("#name").value.trim(),
      email: $("#regEmail").value.trim(),
      phone: $("#phone").value.trim(),
      password: $("#regPassword").value
    };

    if (!payload.name || !payload.email || !payload.phone || !payload.password) {
      showAlert($("#registerAlert"), "Please complete all fields.");
      return;
    }

    const { response, data } = await api("/api/register", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      showAlert($("#registerAlert"), data.message || "Registration failed.");
      return;
    }

    registrationChallengeId = data.challengeId;
    registrationUserId = null;
    registerCard.classList.add("hidden");
    emailOtpCard.classList.remove("hidden");
    $("#emailOtp").focus();
  });

  $("#emailOtpForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const otp = $("#emailOtp").value.trim();
    if (!/^\d{6}$/.test(otp)) {
      showAlert($("#emailAlert"), "Enter the 6-digit OTP.");
      return;
    }

    const { response, data } = await api("/api/verify-email-otp", {
      method: "POST",
      body: JSON.stringify({
        challengeId: registrationChallengeId,
        otp
      })
    });

    if (!response.ok) {
      showAlert(
        $("#emailAlert"),
        data.attemptsRemaining
          ? `${data.message} Attempts remaining: ${data.attemptsRemaining}.`
          : data.message
      );
      return;
    }

    registrationUserId = data.userId;
    emailOtpCard.classList.add("hidden");
    smsOtpCard.classList.remove("hidden");
  });

  $("#resendEmailOtp").addEventListener("click", async () => {
    const { response, data } = await api("/api/send-email-otp", {
      method: "POST",
      body: JSON.stringify({ challengeId: registrationChallengeId })
    });

    if (!response.ok) {
      showAlert($("#emailAlert"), data.message || "Could not resend OTP.");
      return;
    }

    registrationChallengeId = data.challengeId;
    showAlert($("#emailAlert"), "New email OTP generated. Check the server console.", "success");
  });

  $("#sendSmsOtp").addEventListener("click", async () => {
    const { response, data } = await api("/api/send-sms-otp", {
      method: "POST",
      body: JSON.stringify({ userId: registrationUserId })
    });

    if (!response.ok) {
      showAlert($("#smsAlert"), data.message || "Could not send SMS OTP.");
      return;
    }

    $("#sendSmsOtp").classList.add("hidden");
    $("#smsOtpForm").classList.remove("hidden");
    registrationChallengeId = data.challengeId;
    $("#smsOtp").focus();
    showAlert($("#smsAlert"), "SMS OTP generated. Check the server console.", "success");
  });

  $("#smsOtpForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const otp = $("#smsOtp").value.trim();

    if (!/^\d{6}$/.test(otp)) {
      showAlert($("#smsAlert"), "Enter the 6-digit OTP.");
      return;
    }

    const { response, data } = await api("/api/verify-sms-otp", {
      method: "POST",
      body: JSON.stringify({
        userId: registrationUserId,
        challengeId: registrationChallengeId,
        otp
      })
    });

    if (!response.ok) {
      showAlert(
        $("#smsAlert"),
        data.attemptsRemaining
          ? `${data.message} Attempts remaining: ${data.attemptsRemaining}.`
          : data.message
      );
      return;
    }

    smsOtpCard.classList.add("hidden");
    successCard.classList.remove("hidden");
  });
}

// ---------- Dashboard ----------

if ($("#userName")) {
  async function loadDashboard() {
    const { response, data } = await api("/api/me");

    if (!response.ok || !data.authenticated) {
      window.location.href = "/";
      return;
    }

    $("#userName").textContent = data.user.name;
    $("#userEmail").textContent = data.user.email;
    $("#userPhone").textContent = data.user.phone;
    $("#apiStatus").textContent = "Session authenticated ✓";
  }

  loadDashboard();

  $("#logoutButton").addEventListener("click", async () => {
    const { response } = await api("/api/logout", { method: "POST" });

    if (response.ok) {
      window.location.href = "/";
    }
  });
}
