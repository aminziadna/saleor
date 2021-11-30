from re import match
import uuid
from typing import Optional, List
import requests
import json

from saleor.core import transactions

from ... import PaymentError, TransactionKind

from ...models import Payment, Transaction
from saleor.payment import gateway

from ...interface import GatewayConfig, GatewayResponse, PaymentData, PaymentMethodInfo, CustomerSource

import logging

logger = logging.getLogger(__name__)

TOKEN_PREAUTHORIZE_SUCCESS = "4111111111111112"
TOKEN_PREAUTHORIZE_DECLINE = "4111111111111111"
TOKEN_EXPIRED = "4000000000000069"
TOKEN_INSUFFICIENT_FUNDS = "4000000000009995"
TOKEN_INCORRECT_CVV = "4000000000000127"
TOKEN_DECLINE = "4000000000000002"

PREAUTHORIZED_TOKENS = [TOKEN_PREAUTHORIZE_DECLINE, TOKEN_PREAUTHORIZE_SUCCESS]

TOKEN_VALIDATION_MAPPING = {
    TOKEN_EXPIRED: "Card expired",
    TOKEN_INSUFFICIENT_FUNDS: "Insufficient funds",
    TOKEN_INCORRECT_CVV: "Incorrect CVV",
    TOKEN_DECLINE: "Card declined",
    TOKEN_PREAUTHORIZE_DECLINE: "Card declined",
}


def dummy_success():
    return True

def get_client_token(**_):
    return str(uuid.uuid4())

def previusToken(customer_id:str):
    transaction = (
            Transaction.objects.filter(
                kind=TransactionKind.AUTH,
                is_success=True,
                customer_id=customer_id
            )
            .exclude(token__isnull=False, token__exact="",gateway_response__isnull=False,gateway_response__exact="")
            .last()
        )

    if not transaction:
        # If we don't find the Auth kind we will try to get Capture kind
        transaction = (
            Transaction.objects.filter(
                kind=TransactionKind.CAPTURE,
                is_success=True,
                customer_id=customer_id
            )
            .exclude(token__isnull=False, token__exact="",gateway_response__isnull=False,gateway_response__exact="")
            .last()
        )
    last_card = json.loads(transaction.gateway_response)
    return last_card["TranzilaTK"]



def getTokenExpDateFromTranzila(token:str,customer_id:str) -> str:
    t = token[0:token.find("&")]
    if t == "null":
        return previusToken(customer_id[0:10])
    url = "https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi"
    payload='supplier=test&TranzilaPW=test&ccno='+token[0:token.find("&")]+'&TranzilaTK=1&response_return_format=json'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()
    return data["TranzilaTK"][0:len(data["TranzilaTK"]) - 1]

def authorize(
    payment_information: PaymentData, config: GatewayConfig
) -> GatewayResponse:
    payment_information.reuse_source = True
    token = getTokenExpDateFromTranzila(payment_information.token,payment_information.customer_email)
    expdate = payment_information.token[len(payment_information.token)-4:len(payment_information.token)]
    dataQuery = 'TranzilaTK='+token+'&currency=1&supplier=test&tranmode=V&mycvv=123&sum='+str(payment_information.amount)+'&cred_type=1&TranzilaPW=test&response_return_format=json&expdate='+expdate
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.request("POST","https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi",data=dataQuery,headers=headers)
    data = response.json()
    if(data["Response"] == "000" or data["Response"] == "003"):
        return GatewayResponse(
            is_success=True,
            action_required=False,
            kind=TransactionKind.AUTH,
            amount=payment_information.amount,
            currency=payment_information.currency,
            transaction_id=payment_information.token or "",
            customer_id=payment_information.customer_email[0:10],
            raw_response=response.text,
            error=None,
            
            payment_method_info=PaymentMethodInfo(
                exp_month=expdate[0:2],
                exp_year=expdate[2:4],
                last_4= _normalize_last_4_digit(token),
                brand= _get_brand_type(data["cardissuer"]),
                type="card",
            ),
        )
    else: 
        return GatewayResponse(
            is_success=False,
            action_required=False,
            kind=TransactionKind.AUTH,
            amount=payment_information.amount,
            currency=payment_information.currency,
            transaction_id=payment_information.token or "",
            raw_response=response.text,
            error= response.text[255:min(len(response.text),510)],
        )
# need to fix
def void(payment_information: PaymentData, config: GatewayConfig) -> GatewayResponse:
    transaction = (
            Transaction.objects.filter(
                payment__id=payment_information.payment_id,
                kind=TransactionKind.AUTH,
                is_success=True,
            )
            .exclude(token__isnull=False, token__exact="")
            .last()
        )

    if not transaction:
        # If we don't find the Auth kind we will try to get Capture kind
        transaction = (
            Transaction.objects.filter(
                payment__id=payment_information.payment_id,
                kind=TransactionKind.CAPTURE,
                is_success=True,
            )
            .exclude(token__isnull=False, token__exact="")
            .last()
        )

    if not transaction:
        raise PaymentError("Cannot find a payment reference to refund.")
    
    gwresponse = json.loads(transaction.gateway_response)

    url = "https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi"

    payload=f'supplier=test&TranzilaPW=test&CreditPass=test&tranmode=D{gwresponse["index"]}&authnr={gwresponse["ConfirmationCode"]}&TranzilaTK={gwresponse["TranzilaTK"]}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()
    err = None
    if data["Response"] == "000":
        err = data['error_msg']
    return GatewayResponse(
        is_success=data["Response"] == "000",
        action_required=False,
        kind=TransactionKind.VOID,
        amount=payment_information.amount,
        currency=payment_information.currency,
        transaction_id=payment_information.token or "",
        error=err,
    )


def capture(payment_information: PaymentData, config: GatewayConfig) -> GatewayResponse:
    """Perform capture transaction."""
    url = "https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi"
    payment_information.reuse_source = True
    token = getTokenExpDateFromTranzila(payment_information.token,payment_information.customer_email)
    expdate = payment_information.token[len(payment_information.token)-4:len(payment_information.token)]
    payload=f'TranzilaTK={token}&supplier=test&tranmode=A&expdate={expdate}&sum={str(payment_information.amount)}&TranzilaPW=test&currency=1&cred_type=1&response_return_format=json'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()
    if data["Response"] == "000" or data["Response"] == "003":
        return GatewayResponse(
            is_success=True,
            action_required=False,
            kind=TransactionKind.CAPTURE,
            customer_id=payment_information.customer_email[0:10],
            amount=payment_information.amount,
            currency=payment_information.currency,
            transaction_id=payment_information.token or "",
            raw_response=response.text,
            error=None,
            payment_method_info=PaymentMethodInfo(
                last_4= _normalize_last_4_digit(payment_information.token),
                brand= _get_brand_type(data["cardissuer"]),
                type="card",
            ),
        )
    else: 
        return GatewayResponse(
            is_success=False,
            action_required=False,
            kind=TransactionKind.CAPTURE,
            amount=payment_information.amount,
            currency=payment_information.currency,
            transaction_id=payment_information.token or "",
            raw_response=response.text,
            error= response.text[255:min(len(response.text),510)],
        )


def confirm(payment_information: PaymentData, config: GatewayConfig) -> GatewayResponse:
    """Perform confirm transaction."""
    return capture(payment_information, gateway)

#fix me
def refund(payment_information: PaymentData, config: GatewayConfig) -> GatewayResponse:
    transaction = (
            Transaction.objects.filter(
                payment__id=payment_information.payment_id,
                kind=TransactionKind.AUTH,
                is_success=True,
            )
            .exclude(token__isnull=False, token__exact="")
            .last()
        )

    if not transaction:
        # If we don't find the Auth kind we will try to get Capture kind
        transaction = (
            Transaction.objects.filter(
                payment__id=payment_information.payment_id,
                kind=TransactionKind.CAPTURE,
                is_success=True,
            )
            .exclude(token__isnull=False, token__exact="")
            .last()
        )

    if not transaction:
        raise PaymentError("Cannot find a payment reference to refund.")
    
    gwresponse = json.loads(transaction.gateway_response)

    url = "https://secure5.tranzila.com/cgi-bin/tranzila71u.cgi"
    token = getTokenExpDateFromTranzila(payment_information.token, payment_information.customer_email)

    payload=f'expdate={gwresponse["expdate"]}&CreditPass=test&tranmode=C{gwresponse["index"]}&authnr={gwresponse["ConfirmationCode"]}&TranzilaTK={token}&currency=1&supplier=test&sum={str(payment_information.amount)}&cred_type={gwresponse["cred_type"]}&TranzilaPW=test&response_return_format=json'
    raise Exception(payload)
    headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    data = response.json()
    err = None
    if data["Response"] == "000":
        err = data['error_msg']

    return GatewayResponse(
        is_success=data["Response"] == "000",
        action_required=False,
        kind=TransactionKind.REFUND,
        amount=payment_information.amount,
        currency=payment_information.currency,
        transaction_id=payment_information.token or "",
        error=err,
    )


def process_payment(
    payment_information: PaymentData, config: GatewayConfig
) -> GatewayResponse:
    return capture(payment_information, config)

def list_client_sources(config: GatewayConfig, customer_id: str) -> List[CustomerSource]:
    transaction = (
            Transaction.objects.filter(
                kind=TransactionKind.AUTH,
                is_success=True,
                customer_id=customer_id
            )
            .exclude(token__isnull=False, token__exact="",gateway_response__isnull=False,gateway_response__exact="")
            .last()
        )

    if not transaction:
        # If we don't find the Auth kind we will try to get Capture kind
        transaction = (
            Transaction.objects.filter(
                kind=TransactionKind.CAPTURE,
                is_success=True,
                customer_id=customer_id
            )
            .exclude(token__isnull=False, token__exact="",gateway_response__isnull=False,gateway_response__exact="")
            .last()
        )
    last_card = json.loads(transaction.gateway_response)
    return [
        CustomerSource(
            id="token1",
            gateway="mirumee.payments.dummy_credit_card",
            credit_card_info=PaymentMethodInfo(
                exp_year=last_card["expdate"][2:4],
                exp_month=last_card["expdate"][0:2],
                last_4=_normalize_last_4_digit(last_card["TranzilaTK"]),
                brand=_get_brand_type(str(last_card["cardissuer"])),
                type="card"
            ),
        )
    ]

def _normalize_last_4_digit(token:str):
    if len(token) > 4:
        return token[len(token) - 4: len(token)]
    return ""

def _get_brand_type(issuer:str):
    if issuer == "1":
        return "MasterCard"
    return "Visa"