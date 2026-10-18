(() => {
  "use strict";
  const pages = ["dashboard", "emails", "websites", "social", "protection", "media", "lab", "response", "qr", "messages", "workplace", "accounts", "privacy", "scenarios", "glossary", "ai-fraud", "cloud-security", "mobile-security", "soc-lab", "threat-intel", "reporting", "email-forensics", "identity-defense", "security-drills", "progress", "quiz"];
  const pageTitles = {dashboard:"Dashboard",emails:"Phishing emails",websites:"Fake websites",social:"Social engineering",protection:"Stay protected",media:"Video & resources",lab:"Phishing simulation lab",response:"Incident response",qr:"QR code phishing",messages:"SMS & phone scams",workplace:"Workplace fraud",accounts:"Passwords & MFA",privacy:"Privacy & device safety",scenarios:"Scenario practice",glossary:"Glossary & FAQ","ai-fraud":"AI & deepfake scams","cloud-security":"Cloud & collaboration","mobile-security":"Mobile security","soc-lab":"SOC analyst lab","threat-intel":"Threat intelligence",reporting:"Reporting & policy","email-forensics":"Email forensics","identity-defense":"Identity attack defence","security-drills":"Security decision drills",progress:"My progress & certificate",quiz:"Final knowledge check"};
  const STORAGE_KEY = "securewise-pro-v1";
  let savedState = {};
  try { savedState = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); } catch (_) { savedState = {}; }
  const completed = new Set(savedState.completed || []);
  const quickAnswered = new Set(savedState.quickAnswered || []);
  function saveState() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({completed:[...completed], quickAnswered:[...quickAnswered], safety:checklist.map(c=>c.checked), response:responseChecks.map(c=>c.checked), quizScore:localStorage.getItem(STORAGE_KEY+"-quiz") || null})); } catch (_) {}
    updateProDashboard();
  }
  const nav = [...document.querySelectorAll("[data-page]")];
  const pageEls = [...document.querySelectorAll(".page")];
  const toast = document.getElementById("toast");
  let toastTimer;
  function showToast(message) {
    toast.textContent = message; toast.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove("show"), 2600);
  }
  function goToPage(name) {
    if (!pages.includes(name)) return;
    pageEls.forEach(el => el.classList.toggle("active", el.id === `page-${name}`));
    document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.page === name));
    document.getElementById("crumbCurrent").textContent = pageTitles[name];
    document.getElementById("sidebar").classList.remove("open");
    window.scrollTo({top:0, behavior:"smooth"});
  }
  nav.forEach(el => el.addEventListener("click", e => { e.preventDefault(); goToPage(el.dataset.page); }));
  document.getElementById("mobileMenu").addEventListener("click", () => document.getElementById("sidebar").classList.toggle("open"));
  document.addEventListener("click", e => {
    const side = document.getElementById("sidebar");
    if (window.innerWidth <= 850 && side.classList.contains("open") && !side.contains(e.target) && !e.target.closest("#mobileMenu")) side.classList.remove("open");
  });
  function updateProgress() {
    const count = completed.size;
    document.getElementById("completedStat").textContent = String(count).padStart(2,"0");
    document.getElementById("completionPercent").textContent = `${Math.round(count/4*100)}%`;
    document.getElementById("progressLabel").textContent = `${count} of 4 completed`;
    document.getElementById("progressBar").style.width = `${count/4*100}%`;
    completed.forEach(id => {
      const status = document.getElementById(`status-${id}`);
      if (status) { status.textContent = "Completed ✓"; status.classList.add("done"); }
    });
    ["emails","websites","social","protection"].filter(id => !completed.has(id)).forEach(id => {
      const status = document.getElementById(`status-${id}`);
      if (status) { status.textContent = "Not started"; status.classList.remove("done"); }
    });
  }
  document.querySelectorAll("[data-complete]").forEach(btn => btn.addEventListener("click", () => {
    const id = btn.dataset.complete;
    if (!completed.has(id)) { completed.add(id); updateProgress(); saveState(); showToast("Lesson marked complete. Great progress!"); }
    else showToast("This lesson is already marked complete.");
    btn.innerHTML = "Lesson completed ✓"; btn.classList.add("btn-secondary"); btn.classList.remove("btn-primary");
  }));
  document.querySelectorAll(".answer-options").forEach(group => {
    group.querySelectorAll(".answer-option").forEach(btn => btn.addEventListener("click", () => {
      if (quickAnswered.has(group.dataset.quick)) return;
      const correct = btn.dataset.answer === "correct";
      group.querySelectorAll(".answer-option").forEach(option => {
        option.disabled = true;
        if (option.dataset.answer === "correct") option.classList.add("correct");
      });
      if (!correct) btn.classList.add("incorrect");
      const feedback = group.querySelector(".feedback");
      feedback.textContent = correct ? "Correct — verify independently before sharing information." : "Not quite. The safest choice is to verify using a trusted route.";
      feedback.style.color = correct ? "#177d66" : "#b8433d";
      quickAnswered.add(group.dataset.quick); saveState();
      const pageId = group.dataset.quick;
      if (correct) showToast("Correct answer!");
    }));
  });
  const checklist = [...document.querySelectorAll("#safetyChecklist input[type=checkbox]")];
  function updateChecklist() {
    const count = checklist.filter(c => c.checked).length;
    document.getElementById("checklistCount").textContent = `${count} of ${checklist.length} completed`;
    document.getElementById("checklistPercent").textContent = `${Math.round(count/checklist.length*100)}%`;
    document.getElementById("checklistBar").style.width = `${count/checklist.length*100}%`;
  }
  checklist.forEach((c,i) => { c.checked = !!(savedState.safety || [])[i]; c.addEventListener("change", () => { updateChecklist(); saveState(); }); });
  const answers = {q0:"b",q1:"c",q2:"b",q3:"c",q4:"b",q5:"b",q6:"c",q7:"b",q8:"c",q9:"b",q10:"a",q11:"c",q12:"a",q13:"b",q14:"c",q15:"a",q16:"b",q17:"c",q18:"a",q19:"b",q20:"c",q21:"a",q22:"b",q23:"c",q24:"a",q25:"b",q26:"c",q27:"a",q28:"b",q29:"c",q30:"a",q31:"b",q32:"c",q33:"b",q34:"a"};
  const explanations = {
    q0:"Use the official app or a known address. Email links can lead to convincing fake sign-in pages.",
    q1:"HTTPS encrypts data in transit; it does not guarantee the website is legitimate.",
    q2:"Never share a one-time code. Verify the caller through an official support route.",
    q3:"Urgency and secrecy are common pressure tactics used in social engineering.",
    q4:"Change the exposed password using the official site, contact support, and report the incident promptly.",
    q5:"Supplier bank-detail changes are high risk. Verify independently using a previously trusted contact method and follow approval controls.",
    q6:"QR codes can conceal destinations. Do not enter credentials unless the destination and request are verified.",
    q7:"Broad access should be treated cautiously. Verify the app and whether the permission is necessary and approved.",
    q8:"Voice imitation is possible. Familiar-sounding audio does not replace independent verification.",
    q9:"Unexpected MFA approvals can indicate an attempted or successful sign-in. Report promptly and follow official account-recovery steps.",
    q10:"HTTPS protects data in transit; it does not prove that the site operator is trustworthy.",
    q11:"Unexpected file shares can be impersonation lures. Confirm context and use the official service.",
    q12:"Secure the account promptly, change reused passwords, review active sessions where available and report the incident.",
    q13:"Independent verification and separation of duties reduce the risk of payment redirection fraud.",
    q14:"AI can generate convincing messages. Use context and verification rather than relying on grammar.",

    q15:"Report through the approved process and avoid spreading or opening the suspicious content.",
    q16:"A tampered QR code may redirect payments or credentials. Use a verified method and alert the responsible party.",
    q17:"Unsolicited remote-access requests are high risk. Verify independently with the service provider.",
    q18:"Authentication signals are useful evidence, not a guarantee that the request or destination is benign.",
    q19:"Never put passwords, one-time codes or unnecessary sensitive information into an incident report.",
    q20:"Good threat-intelligence handling records provenance and uncertainty and seeks corroboration.",
    q21:"Unexpected broad permissions can expose data. Review necessity and approval before granting access.",
    q22:"Separation of duties and independent checks help prevent payment redirection and impersonation fraud.",
    q23:"Establish whether the sign-in was expected and whether an approval occurred, then follow account-security procedures.",
    q24:"Clear reports state what is known, what is uncertain and what actions have been taken; urgent concerns should not be delayed.",
    q25:"Display names can be spoofed. Verify unusual or high-impact requests through a trusted independent channel.",
    q26:"Authentication helps assess sending-domain signals but does not guarantee content or attachments are safe.",
    q27:"A compromised session may remain active. Escalate and use official procedures to secure the account.",
    q28:"Unsolicited remote-access requests can expose a device. Verify through known support channels.",
    q29:"Do not visit suspicious destinations casually or spread them. Use approved defensive procedures.",
    q30:"Reporting allows security staff to assess potential exposure and preserve relevant evidence.",
    q31:"Independent verification and separation of duties help detect fraudulent payment changes.",
    q32:"Broad permissions can expose sensitive data. Grant only necessary, approved access.",
    q33:"Professional analysis distinguishes observations from conclusions and records uncertainty.",
    q34:"Accurate facts and actions help response. Never include passwords or one-time authentication codes."

  };
  const quizForm = document.getElementById("quizForm");
  quizForm.addEventListener("submit", e => {
    e.preventDefault();
    let score = 0, unanswered = 0;
    Object.keys(answers).forEach((key, index) => {
      const question = document.querySelector(`.quiz-question[data-q="${index}"]`);
      const chosen = quizForm.querySelector(`input[name="${key}"]:checked`);
      const feedback = question.querySelector(".question-feedback");
      question.classList.remove("correct-answer","wrong-answer");
      if (!chosen) unanswered++;
      const isCorrect = chosen && chosen.value === answers[key];
      if (isCorrect) score++;
      question.classList.add(isCorrect ? "correct-answer" : "wrong-answer");
      feedback.textContent = `${isCorrect ? "✓ Correct. " : "✕ Review. "}${explanations[key]}`;
      feedback.style.color = isCorrect ? "#16866f" : "#b84b44";
    });
    if (unanswered) showToast(`${unanswered} question${unanswered===1?"":"s"} unanswered — review them below.`);
    document.getElementById("resultScore").textContent = `${score}/${Object.keys(answers).length}`;
    try { localStorage.setItem(STORAGE_KEY+"-quiz", String(score)); } catch (_) {}
    saveState();
    const total = Object.keys(answers).length; const title = score === total ? "Excellent work!" : score >= Math.ceil(total * 0.7) ? "Good progress!" : "Keep practising!";
    document.getElementById("resultTitle").textContent = title;
    document.getElementById("resultMessage").textContent = score === Object.keys(answers).length ? "You spotted every safe choice. Keep applying these habits in real situations." : "Review the explanations above, revisit any lesson you need, and try again to build your confidence.";
    document.getElementById("quizResult").hidden = false;
    document.getElementById("quizResult").scrollIntoView({behavior:"smooth",block:"center"});
  });
  document.getElementById("retryQuiz").addEventListener("click", () => {
    quizForm.reset();
    document.querySelectorAll(".quiz-question").forEach(q => { q.classList.remove("correct-answer","wrong-answer"); q.querySelector(".question-feedback").textContent = ""; });
    document.getElementById("quizResult").hidden = true;
    goToPage("quiz");
    showToast("Quiz reset. Give it another try!");
  });
  


  const reportForm = document.getElementById("reportBuilder");
  const reportOutput = document.getElementById("reportOutput");
  if (reportForm && reportOutput) {
    reportForm.addEventListener("submit", event => {
      event.preventDefault();
      const category = document.getElementById("reportCategory").value;
      const when = document.getElementById("reportWhen").value.trim() || "Not specified";
      const observed = document.getElementById("reportObserved").value.trim() || "Not specified";
      const action = document.getElementById("reportAction").value.trim() || "Not specified";
      reportOutput.value = `SECURITY AWARENESS REPORT DRAFT\nCategory: ${category}\nTime: ${when}\nObserved facts: ${observed}\nAction taken: ${action}\n\nNote: Review and submit through the organization's approved reporting channel. Do not include passwords, MFA codes or unnecessary personal data.`;
      document.getElementById("reportStatus").textContent = "Draft generated locally. Review it carefully before using the official reporting process.";
    });
    document.getElementById("copyReport").addEventListener("click", async () => {
      if (!reportOutput.value) { document.getElementById("reportStatus").textContent = "Generate a report draft first."; return; }
      try {
        await navigator.clipboard.writeText(reportOutput.value);
        document.getElementById("reportStatus").textContent = "Report draft copied. It has not been sent anywhere.";
      } catch (_) {
        reportOutput.focus(); reportOutput.select();
        document.getElementById("reportStatus").textContent = "Clipboard access was unavailable; the report draft is selected so you can copy it manually.";
      }
    });
  }

  document.querySelectorAll(".inline-choice-group").forEach(group => {
    const feedback = group.parentElement.querySelector(".inline-choice-feedback");
    group.querySelectorAll(".inline-choice").forEach(button => {
      button.addEventListener("click", () => {
        group.querySelectorAll(".inline-choice").forEach(item => item.classList.remove("selected"));
        button.classList.add("selected");
        const correct = button.dataset.choice === group.dataset.correct;
        feedback.className = "inline-choice-feedback " + (correct ? "good" : "review");
        feedback.textContent = (correct ? "✓ Correct. " : "↻ Review. ") + group.dataset.explain;
      });
    });
  });

  const reviewEvidence = document.getElementById("reviewEvidence");
  if (reviewEvidence) reviewEvidence.addEventListener("click", () => {
    const chosen = [...document.querySelectorAll("#evidenceOptions input:checked")].map(input => input.value);
    const expected = ["urgency","sender","secrecy","credential"];
    const correctCount = chosen.filter(value => expected.includes(value)).length;
    const falsePositive = chosen.includes("safe");
    const result = document.getElementById("evidenceResult"); result.hidden = false;
    result.className = "evidence-result " + (correctCount === 4 && !falsePositive ? "good" : "review");
    if (correctCount === 4 && !falsePositive) { result.innerHTML = "<strong>Excellent investigation — 4/4 warning signs found.</strong><br>You identified pressure, an unverified sender, secrecy and an unexpected sensitive request. Verify through a trusted HR channel and report the message."; showToast("Simulation completed: all warning signs found."); }
    else { result.innerHTML = `<strong>Good practice — review your evidence.</strong><br>You selected ${correctCount} of 4 genuine warning signs${falsePositive ? " and selected one misleading clue" : ""}. Look for urgency, sender mismatch, secrecy and the unexpected payroll request.`; }
  });
  const responseChecks = [...document.querySelectorAll("#responseChecklist input[type=checkbox]")];
  function updateResponseChecklist() { const count = responseChecks.filter(input => input.checked).length; const el = document.getElementById("responseCount"); if (!el) return; el.textContent = `${count} of ${responseChecks.length} completed`; document.getElementById("responsePercent").textContent = `${Math.round(count/responseChecks.length*100)}%`; document.getElementById("responseBar").style.width = `${count/responseChecks.length*100}%`; }
  responseChecks.forEach((input,i) => { input.checked = !!(savedState.response || [])[i]; input.addEventListener("change", () => { updateResponseChecklist(); saveState(); }); });

  function updateProDashboard() {
    const core = ["emails","websites","social","protection"];
    const count = core.filter(id=>completed.has(id)).length;
    const pct = Math.round(count/core.length*100);
    const p = document.getElementById("proProgressPercent"); if (!p) return;
    p.textContent = `${pct}%`; document.getElementById("proLessons").textContent = `${count} / ${core.length}`;
    document.getElementById("proQuizScore").textContent = localStorage.getItem(STORAGE_KEY+"-quiz") ? `${localStorage.getItem(STORAGE_KEY+"-quiz")}/5` : "Not taken";
    const checks = document.querySelectorAll("#safetyChecklist input[type=checkbox]");
    const safetyPct = checks.length ? Math.round([...checks].filter(c=>c.checked).length/checks.length*100) : 0;
    document.getElementById("proSafety").textContent = `${safetyPct}%`;
    core.forEach(id=>{ const el=document.getElementById(`proStatus-${id}`); if(el){el.textContent=completed.has(id)?"Completed ✓":"Not complete";el.classList.toggle("is-done",completed.has(id));}});
    const hint=document.getElementById("certificateHint"), btn=document.getElementById("printCertificate");
    const quizDone=!!localStorage.getItem(STORAGE_KEY+"-quiz");
    if (hint && btn) { const unlocked=count===core.length && quizDone; btn.disabled=!unlocked; hint.textContent=unlocked?"Unlocked — enter your name, then print or save as PDF.":`Complete ${core.length-count} more core lesson(s) and submit the final quiz to unlock.`; }
    const date=document.getElementById("certificateDate"); if(date) date.textContent="Date: "+new Date().toLocaleDateString(undefined,{year:"numeric",month:"long",day:"numeric"});
  }
  const printBtn=document.getElementById("printCertificate");
  if(printBtn) printBtn.addEventListener("click",()=>{ if(printBtn.disabled){showToast("Complete the core lessons and quiz first.");return;} const name=document.getElementById("certificateName").value.trim(); if(!name){showToast("Enter your name on the certificate first.");document.getElementById("certificateName").focus();return;} document.body.classList.add("printing-certificate"); window.print(); setTimeout(()=>document.body.classList.remove("printing-certificate"),500); });
  const exportBtn=document.getElementById("exportProgress");
  if(exportBtn) exportBtn.addEventListener("click",()=>{ const core=["emails","websites","social","protection"]; const lines=["SECUREWISE — PHISHING AWARENESS TRAINING SUMMARY", "Generated: "+new Date().toLocaleString(), "Lessons completed: "+core.filter(id=>completed.has(id)).length+"/4", "Completed lessons: "+(core.filter(id=>completed.has(id)).join(", ")||"None"), "Latest quiz score: "+(localStorage.getItem(STORAGE_KEY+"-quiz")||"Not taken")+"/5", "Safety checklist: "+document.querySelectorAll("#safetyChecklist input:checked").length+" completed", "Note: This summary is stored/generated locally and is not an accredited certificate."]; const blob=new Blob([lines.join("\n")],{type:"text/plain;charset=utf-8"}); const url=URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url;a.download="SecureWise_Progress_Summary.txt";a.click();URL.revokeObjectURL(url); });
  const resetBtn=document.getElementById("resetProgress");
  if(resetBtn) resetBtn.addEventListener("click",()=>{ if(!confirm("Reset saved SecureWise progress on this browser? This cannot be undone.")) return; localStorage.removeItem(STORAGE_KEY);localStorage.removeItem(STORAGE_KEY+"-quiz");completed.clear();quickAnswered.clear();checklist.forEach(c=>c.checked=false);responseChecks.forEach(c=>c.checked=false);document.querySelectorAll(".mark-complete").forEach(b=>{b.innerHTML="Mark lesson complete <span>✓</span>";b.classList.add("btn-primary");b.classList.remove("btn-secondary");});updateProgress();updateChecklist();updateResponseChecklist();saveState();showToast("Local progress reset.");});
  const themeToggle=document.getElementById("themeToggle");
  if(themeToggle){ if(localStorage.getItem("securewise-theme")==="contrast") document.body.classList.add("high-contrast"); themeToggle.addEventListener("click",()=>{document.body.classList.toggle("high-contrast");localStorage.setItem("securewise-theme",document.body.classList.contains("high-contrast")?"contrast":"standard");});}
  updateProgress(); updateChecklist(); updateResponseChecklist();

  // Persist the additional topic checklists locally without transmitting data.
  const extraChecklistIds = ["qrChecklist", "privacyChecklist"];
  extraChecklistIds.forEach(id => {
    const list = document.getElementById(id);
    if (!list) return;
    const inputs = [...list.querySelectorAll('input[type="checkbox"]')];
    const key = STORAGE_KEY + "-" + id;
    let saved = [];
    try { saved = JSON.parse(localStorage.getItem(key) || "[]"); } catch (_) {}
    inputs.forEach((input, i) => {
      input.checked = !!saved[i];
      input.addEventListener("change", () => {
        try { localStorage.setItem(key, JSON.stringify(inputs.map(item => item.checked))); } catch (_) {}
      });
    });
  });
 updateProDashboard();
})();