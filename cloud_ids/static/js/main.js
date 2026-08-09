/* Cloud IDS - Main JavaScript */

// Auto-dismiss flash alerts after 5 seconds
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    document.querySelectorAll(".alert.alert-dismissible").forEach(el => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      bsAlert.close();
    });
  }, 5000);
});
