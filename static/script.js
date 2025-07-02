document.addEventListener('DOMContentLoaded', () => {
    const loader = document.getElementById('loader');
    const mainContainer = document.querySelector('.container');
    // --- DOM Elements ---
    const nicknameInput = document.getElementById('nickname-input');
    const newEmailBtn = document.getElementById('new-email-btn');
    const emailList = document.getElementById('email-list');
    const currentEmailText = document.getElementById('current-email-text');
    const inboxList = document.getElementById('inbox-list');
    const refreshInboxBtn = document.getElementById('refresh-inbox-btn');
    const emailContentView = document.getElementById('email-content-view');
    const emailFrom = document.getElementById('email-from');
    const emailSubject = document.getElementById('email-subject');
    const emailBody = document.getElementById('email-body');
    const closeModalBtn = document.querySelector('.close-btn');

    // --- App State ---
    let state = {
        emails: [], // Array of {id, nickname, email}
        current_email_id: null,
    };

    // --- API Helper ---
    const api = {
        async request(method, url, data) {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' },
            };
            if (data) {
                options.body = JSON.stringify(data);
            }
            try {
                const response = await fetch(url, options);
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: `API request failed with status ${response.status}` }));
                    throw new Error(errorData.error || 'Unknown error');
                }
                return response.status !== 204 ? response.json() : null;
            } catch (e) {
                console.error('API request error:', e.message);
                alert(`Error: ${e.message}`);
                throw e;
            }
        },
        get(url) { return this.request('GET', url); },
        post(url, data) { return this.request('POST', url, data); },
    };

    // --- UI Rendering ---
    function renderEmailList() {
        emailList.innerHTML = '';
        let currentEmailInList = false;
        state.emails.forEach(account => {
            const li = document.createElement('li');
            li.dataset.id = account.id;
            li.innerHTML = `
                <span class="nickname">${account.nickname}</span>
                <span class="email-address">${account.email}</span>
                <div class="actions">
                    <button class="delete-email-btn" title="Delete Email">🗑️</button>
                </div>
            `;
            if (account.id === state.current_email_id) {
                li.classList.add('active');
                currentEmailText.textContent = account.email;
                currentEmailInList = true;
            }
            emailList.appendChild(li);
        });
        if (!currentEmailInList) {
            currentEmailText.textContent = 'None';
            state.current_email_id = null;
            inboxList.innerHTML = '<p>No email selected.</p>';
        }
    }

    function renderInbox(messages) {
        inboxList.innerHTML = '';
        if (!messages || messages.length === 0) {
            inboxList.innerHTML = '<p>Your inbox is empty.</p>';
            return;
        }
        messages.forEach(message => {
            const div = document.createElement('div');
            div.classList.add('inbox-item');
            div.dataset.id = message.id;
            div.innerHTML = `
                <div class="message-details">
                    <span class="from"><strong>From:</strong> ${message.from}</span>
                    <span class="subject"><strong>Subject:</strong> ${message.subject}</span>
                </div>
                <button class="delete-message-btn" title="Delete Message">🗑️</button>
            `;
            inboxList.appendChild(div);
        });
    }

    // --- Core Logic ---
    async function initializeApp() {
        try {
            const emails = await api.get('/get_emails');
            state.emails = emails;
            if (state.emails.length > 0 && !state.current_email_id) {
                // Default to first email if none is selected
                await useEmail(state.emails[0].id);
            } else {
                renderEmailList();
                if(state.current_email_id) {
                    await refreshInbox();
                }
            }
        } catch (error) {
            // Error already alerted by api helper
        }
    }

    async function createNewEmail() {
        const nickname = nicknameInput.value.trim();
        if (!nickname) {
            alert('Please enter a nickname for the new email.');
            return;
        }
        try {
            const newEmail = await api.post('/new_email', { nickname });
            state.emails.push(newEmail);
            nicknameInput.value = '';
            await useEmail(newEmail.id); // Select the new email automatically
        } catch (error) {
            // Error already alerted
        }
    }

    async function deleteEmail(emailId) {
        try {
            await api.post('/delete_email', { id: emailId });
            state.emails = state.emails.filter(email => email.id !== emailId);
            if (state.current_email_id === emailId) {
                state.current_email_id = null;
                if (state.emails.length > 0) {
                    await useEmail(state.emails[0].id);
                }
            }
            renderEmailList();
             if (!state.current_email_id) {
                inboxList.innerHTML = '<p>No email selected.</p>';
                currentEmailText.textContent = 'None';
            }
        } catch (error) {
            // Error already alerted
        }
    }

    async function useEmail(emailId) {
        try {
            // No need to call API if we are just setting it from the list
            state.current_email_id = emailId;
            renderEmailList();
            await refreshInbox();
        } catch (error) {
            // Error already alerted
        }
    }

    async function refreshInbox() {
        if (!state.current_email_id) {
            inboxList.innerHTML = '<p>No email selected.</p>';
            return;
        }
        try {
            const messages = await api.get(`/inbox?id=${state.current_email_id}`);
            renderInbox(messages);
        } catch (error) {
            inboxList.innerHTML = `<p class="error">Failed to load inbox.</p>`;
        }
    }

    async function readEmail(messageId) {
        if (!state.current_email_id) return;
        try {
            const data = await api.get(`/read_email?id=${messageId}&email_id=${state.current_email_id}`);
            emailFrom.textContent = `From: ${data.from}`;
            emailSubject.textContent = data.subject;
            emailBody.innerHTML = data.body; // Using innerHTML for HTML content
            emailContentView.style.display = 'flex';
        } catch (error) {
            // Error already alerted
        }
    }

    async function deleteMessage(messageId) {
        if (!state.current_email_id) return;
        try {
            await api.post('/delete_message', { id: messageId, email_id: state.current_email_id });
            await refreshInbox();
        } catch (error) {
            // Error already alerted
        }
    }

    // --- Event Listeners ---
    newEmailBtn.addEventListener('click', createNewEmail);

    refreshInboxBtn.addEventListener('click', refreshInbox);

    emailList.addEventListener('click', e => {
        const li = e.target.closest('li');
        if (!li) return;
        const emailId = parseInt(li.dataset.id, 10);

        if (e.target.closest('.delete-email-btn')) {
            if (confirm('Are you sure you want to delete this email account?')) {
                deleteEmail(emailId);
            }
        } else {
            useEmail(emailId);
        }
    });

    inboxList.addEventListener('click', e => {
        const item = e.target.closest('.inbox-item');
        if (!item) return;
        const messageId = item.dataset.id;

        if (e.target.closest('.delete-message-btn')) {
            if (confirm('Are you sure you want to delete this message?')) {
                deleteMessage(messageId);
            }
        } else {
            readEmail(messageId);
        }
    });

    closeModalBtn.addEventListener('click', () => {
        emailContentView.style.display = 'none';
    });

    // Initial data fetch and loader management
    function showApp() {
        if (loader) {
            loader.style.opacity = '0';
            loader.addEventListener('transitionend', () => {
                loader.style.display = 'none';
            });
        }
        if (mainContainer) {
            mainContainer.style.display = 'block';
        }
    }

    // Fetch initial data and then show the app
    async function fetchEmails() {
        try {
            const emails = await api.get('/get_emails');
            state.emails = emails;
            if (state.emails.length > 0 && !state.current_email_id) {
                // Default to first email if none is selected
                await useEmail(state.emails[0].id);
            } else {
                renderEmailList();
                if(state.current_email_id) {
                    await refreshInbox();
                }
            }
        } catch (error) {
            // Error already alerted by api helper
        }
    }

    fetchEmails().finally(() => {
        // Use a timeout to ensure the cool animation is visible for a bit
        setTimeout(showApp, 1500); // Minimum display time for the loader
    });
});
