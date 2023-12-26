
        // JavaScript code to hide flash messages after 4 seconds
        setTimeout(function() {
            var flashMessages = document.querySelectorAll('.flash-message');
            flashMessages.forEach(function(message) {
                message.style.display = 'none';
            });
        }, 4000);  // 4000 milliseconds = 4 seconds
