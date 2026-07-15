"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const sidebar = document.querySelector("#sidebar");
    const menuButton = document.querySelector("#menu-button");
    const updatedElement = document.querySelector("#last-updated");

    if (menuButton && sidebar) {
        menuButton.addEventListener("click", () => {
            const isOpen = sidebar.classList.toggle("open");

            menuButton.setAttribute(
                "aria-expanded",
                String(isOpen)
            );
        });

        document.addEventListener("click", (event) => {
            const clickedSidebar = sidebar.contains(event.target);
            const clickedButton = menuButton.contains(event.target);

            if (
                window.innerWidth <= 820 &&
                sidebar.classList.contains("open") &&
                !clickedSidebar &&
                !clickedButton
            ) {
                sidebar.classList.remove("open");
                menuButton.setAttribute("aria-expanded", "false");
            }
        });
    }

    if (updatedElement) {
        const timestamp = updatedElement.getAttribute("datetime");
        const parsedDate = new Date(timestamp);

        if (!Number.isNaN(parsedDate.getTime())) {
            updatedElement.textContent = parsedDate.toLocaleString();
        }
    }
});