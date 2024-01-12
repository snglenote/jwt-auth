// Type: POST
// Url: http://localhost:3000/api/register
/* Body: {
    "name": "Freddy",
    "email": "fazbear@example.com",
    "password": "fazballs"
    }*/

// Pre-request Script:
for (let i = 1; i <= 100; i++) {
    let newUser = {
        name: `User${i}`,
        email: `user${i}@example.com`,
        password: `pass123`
    };

    pm.environment.set(`user${i}_email`, newUser.email);
    pm.environment.set(`user${i}_password`, newUser.password);

    pm.sendRequest({
        method: 'POST',
        url: 'http://localhost:3000/api/register',
        body: {
            mode: 'raw',
            raw: JSON.stringify(newUser)
        },
        header: 'Content-Type:application/json',
        function (err, res) {
            if (err) {
                console.error(err);
            }
        }
    });
}

