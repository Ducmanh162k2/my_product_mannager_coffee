function addToWishList(element, productID) {
    let productImg = $(element).attr('data-product-img2');
    let productName = $(element).attr('data-product-name2');
    let details = "/product/detail/" + productID;

    $("#modalWLProductName").text(productName);
    $("#modalWLProductName").attr('href', details)
    $("#modalWLProductImg").attr('src', productImg);

    $.ajax({
        url: '/add-to-wishlist/' + productID,
        type: 'GET',
        success: function () {
        }
    });
}