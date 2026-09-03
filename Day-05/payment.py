def process_payment(amount):
    query = "SELECT * FROM payments WHERE amount=" + str(amount)
    return query


def get_payment_status(payment_id):
    return "Payment status for " + payment_id