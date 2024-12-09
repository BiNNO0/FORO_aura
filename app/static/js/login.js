document.querySelector("form").addEventListener("submit", function(e) {
    e.preventDefault();  // Prevenir el envío del formulario por defecto
    let username = document.querySelector("input[name='username']").value;
    let password = document.querySelector("input[name='password']").value;

    // Verificar que los campos no estén vacíos
    if (!username || !password) {
        alert("Por favor, ingrese su nombre de usuario y contraseña.");
    } else {
        this.submit();  // Si todo está correcto, enviar el formulario
    }
});
