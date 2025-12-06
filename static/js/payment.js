function calculatePaymentFees(amount) {
    // Calculate all fees based on amount
    const platformFee = amount * 0.10;
    const subtotal = amount + platformFee;
    const vatAmount = subtotal * 0.12;
    const totalAmount = amount + vatAmount;
    const runnerEarnings = amount - platformFee;
    
    return {
        serviceFee: amount.toFixed(2),
        platformFee: platformFee.toFixed(2),
        vatAmount: vatAmount.toFixed(2),
        totalAmount: totalAmount.toFixed(2),
        runnerEarnings: runnerEarnings.toFixed(2)
    };
}

function updateFeeDisplay(amount) {
    const fees = calculatePaymentFees(amount);
    
    document.getElementById('serviceFee').textContent = fees.serviceFee;
    document.getElementById('platformFee').textContent = fees.platformFee;
    document.getElementById('vatAmount').textContent = fees.vatAmount;
    document.getElementById('totalAmount').textContent = fees.totalAmount;
    document.getElementById('runnerEarnings').textContent = fees.runnerEarnings;
    
    document.getElementById('feeBreakdown').style.display = 'block';
}

function toggleWalletPayment() {
    const useWallet = document.getElementById('use_wallet').checked;
    const walletBalance = parseFloat("{{ user.wallet_balance }}");
    
    if (useWallet) {
        document.getElementById('feeBreakdown').style.display = 'block';
        // You can add logic to show wallet-specific information
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Update fees when category price changes
    const categorySelect = document.getElementById('categorySelect');
    if (categorySelect) {
        categorySelect.addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            const basePrice = parseFloat(selectedOption.getAttribute('data-base-price')) || 0;
            if (basePrice > 0) {
                updateFeeDisplay(basePrice);
            }
        });
    }
});