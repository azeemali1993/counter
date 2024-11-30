// Variables
let timer = 10;
let timerInterval = null;
let currentDoor = null; // The door selected by the user
let count = 0; // Local count for the selected door

// DOM Elements
const timerDisplay = document.getElementById('timer-display');
const totalCountDisplay = document.getElementById('total-count-display');
const countDisplay = document.getElementById('count-display');
const addButton = document.getElementById('add-button');
const subtractButton = document.getElementById('subtract-button');
const doorSelectButtons = document.querySelectorAll('.door-select-button');

// Disable/Enable Controls
const disableControls = (disable) => {
    addButton.disabled = disable;
    subtractButton.disabled = disable;
};

// Update Timer Display
const updateTimerDisplay = () => {
    timerDisplay.innerText = `Sync in: ${timer} seconds`;
};

// Update Count Display
const updateCountDisplay = () => {
    countDisplay.innerText = `Local Count: ${count}`;
};

// Fetch Total Count for the Selected Door
const fetchTotalCount = async () => {
    try {
        const response = await fetch('/get_total_count', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ door: currentDoor })
        });

        const data = await response.json();
        if (data.status === 'success') {
            totalCountDisplay.innerText = `Total Count for Selected Door: ${data.total_count}`;
        } else {
            console.error(`Error fetching total count: ${data.error}`);
        }
    } catch (error) {
        console.error('Error fetching total count:', error);
    }
};

// Sync Count with Backend
const syncCount = async () => {
    disableControls(true); // Disable controls during sync
    try {
        const response = await fetch('/update_count', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ door: currentDoor, count: count })
        });

        const data = await response.json();
        if (data.status === 'success') {
            count = 0; // Reset local count
            updateCountDisplay();
            fetchTotalCount(); // Fetch the updated total count
        } else {
        }
    } catch (error) {
        alert('Error syncing count. Please try again.');
    } finally {
        disableControls(false); // Re-enable controls
        startTimer(); // Restart the timer
    }
};

// Timer Logic
const startTimer = () => {
    timer = 10; // Reset timer
    updateTimerDisplay();

    timerInterval = setInterval(() => {
        timer--;
        updateTimerDisplay();

        if (timer <= 0) {
            clearInterval(timerInterval); // Stop the timer
            syncCount(); // Sync the count when the timer hits 0
        }
    }, 1000);
};

// Event Listeners for Door Selection
doorSelectButtons.forEach(button => {
    button.addEventListener('click', () => {
        if (currentDoor) {
            alert('You have already selected a door. Door selection cannot be changed.');
            return;
        }

        currentDoor = button.dataset.door; // Set the selected door
        document.getElementById('door-display').innerText = `Selected Door: ${currentDoor}`;
        button.classList.add('btn-success'); // Highlight the selected door
        fetchTotalCount(); // Fetch total count for the selected door
        startTimer(); // Start the 10-second timer
    });
});

// Event Listeners for Add/Subtract Buttons
addButton.addEventListener('click', () => {
    count++;
    updateCountDisplay();
});

subtractButton.addEventListener('click', () => {
    if (count > 0) {
        count--;
        updateCountDisplay();
    }
});

// Initialize Display
updateTimerDisplay();
updateCountDisplay();
