document.getElementById("set_private_key").addEventListener("click", () => {
    localStorage.setItem("private_key", document.getElementById("private_key").value);
})