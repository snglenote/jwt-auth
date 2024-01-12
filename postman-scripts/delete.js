// Type: DELETE
// Url: http://localhost:3000/api/delete-users
// Params Value: fazbear@example.com

// Pre-request Script:
const commonDomain = '@example.com';

for (let i = 1; i <= 100; i++) {
    let userEmail = `user${i}${commonDomain}`;

    pm.environment.set(`user${i}_email`, userEmail);

    pm.sendRequest({
        method: 'DELETE',
        url: `http://localhost:3000/api/delete-user?email=${userEmail}`,
        header: {
            key: 'Content-Type',
            value: 'application/json'
        },
        function (err, res) {
            if (err) {
                console.error(err);
            }
        }
    });
}
