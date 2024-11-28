
$(document).ready(function () {
    $('.quantity').on('input',function () {
        let quantity = $(this).val();
        let id = $(this).attr('data-id');
        $.ajax({
            url: '/cart/updateCart/' + id + '/' + quantity,
            type: 'GET',
            success: function () {
                location.reload();
            }
        });
    });
});

function updateQuantity(){
    $.ajax({
        url: '/total_items',
        type: 'GET',
        dataType: 'json',
        success: function (data){
            $("#total_items").text(data);
        }
    });
}
function formatPrice(price) {
    return price.toLocaleString('en-US', {
        minimumFractionDigits: 0,
        maximumFractionDigits: 0
    }) + ' VNĐ';
}
function updateSumPrice(){
    $.ajax({
        url: '/getSumPrice',
        type: 'GET',
        dataType: 'json',
        success: function (data){
            let formattedTotalPrice = formatPrice(data);
            $("#sumPrice").text(formattedTotalPrice);
        }
    });
}

function updateCart(){
    $.ajax({
        url: '/getCart',
        type: 'GET',
        dataType: 'json',
        success: function (data){
            if(data.length > 0){
                let bodyCartHTML = '';
                let footerCartHTML ='';

                $.each(data, function(i, item){
                    bodyCartHTML = bodyCartHTML + '<div class="mini-cart-item clearfix">' +
                        '<div class="mini-cart-img">' +
                        '<a href="/product/detail/' + item.productId + '">' +
                        '<img src="' + item.img + '" alt="Image"></a>' +
                        '<span class="mini-cart-item-delete"><i class="icon-cancel"></i></span>' +
                        '</div>' +
                        '<div class="mini-cart-info">' +
                        '<h6><a href="/product/detail/' + item.productId + '">' + item.productName + '</a></h6>' +
                        '<span class="mini-cart-quantity">' +
                        '<span>' + item.quantity + '</span> x ' +
                        '<span>' + formatPrice(item.price) + '</span></span>' +
                        '</div>' +
                        '</div>';
                });

                footerCartHTML = footerCartHTML + '' +
                    '<div class="mini-cart-sub-total">\n' +
                    '    <h5>Subtotal: <span id="sumPrice">$310.00</span>\n' +
                    '    </h5>\n' +
                    '</div>\n' +
                    '<div class="btn-wrapper">\n' +
                    '    <a href="/cart" class="theme-btn-1 btn btn-effect-1">View Cart</a>\n' +
                    '    <a href="/cart/checkout" class="theme-btn-2 btn btn-effect-2">Checkout</a>\n' +
                    '</div>';

                $('#body-cart').empty();
                $('#footer-cart').empty();
                $('#body-cart').append(bodyCartHTML);
                $('#footer-cart').append(footerCartHTML);
                updateSumPrice();
            }
        }
    });
}
function addToCart(element, productID) {
    let productImg = $(element).attr('data-product-img');
    let productName = $(element).attr('data-product-name');
    let details = "/product/detail/" + productID;
    let quantity = $('#quantity').val();
    if(quantity == undefined){
        quantity = 1;
    }
    $("#modalProductName").text(productName);
    $("#modalProductName").attr('href', details)
    $("#modalProductImg").attr('src', productImg);
    // alert("Added to Cart!: " + productID + "Name: "+productName + "Img: "+productImg);
    $.ajax({
            url: '/add-to-cart/' + productID + "/" + quantity,
        type: 'GET',
        success: function () {
            updateQuantity();
            updateCart();
        }
    });
}

//Quick View
function addToCartQV(productId){
    $.ajax({
        url: '/getProduct/' + productId,
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            //show modal add to cart
            let details = "/product/detail/" + productId;
            $("#modalProductName").text(data.name);
            $("#modalProductName").attr('href', details)
            $("#modalProductImg").attr('src', data.image);
            let quantity = $("#quantityQV").val();
            //add to cart
            $.ajax({
                url: '/add-to-cart/' +productId + "/" + quantity,
                type: 'GET',
                success: function () {
                    updateQuantity();
                    updateCart();
                }
            });
        }
    });
}
function addToWishListQV(productID) {
    $.ajax({
        url: '/getProduct/' + productID,
        type: 'GET',
        success: function (data) {
            //show modal wishlist
            let details = "/product/detail/" + productID;
            $("#modalWLProductName").text(data.name);
            $("#modalWLProductName").attr('href', details);
            $("#modalWLProductImg").attr('src', data.image);
            //add to wishlist
            $.ajax({
                url: '/add-to-wishlist/' + productID,
                type: 'GET',
                success: function () {
                }
            });
        }
    });
}
function quickView(productID) {
    $.ajax({
        url: '/getProduct/' + productID,
        type: 'GET',
        dataType: 'json',
        success: function (data) {
            $("#QVName").text(data.name);
            $("#QVPrice").text(formatPrice(data.price));
            $("#QVImg").attr('src',data.image);
            let QVAddToCart ='';
            let QVWishList = '';
            // $("#QVAddToCart").empty();
            // $("#QVWishlist").empty();
           if(data.quantity > 1){
               QVAddToCart = QVAddToCart + ' <a href="#" class="theme-btn-1 btn btn-effect-1"\n' +
                   '                                                               title="Add to Cart" data-bs-toggle="modal"\n' +
                   '                                                               data-bs-target="#add_to_cart_modal" onclick="addToCartQV(\''+data.id+'\',)">\n' +
                   '                                                                <i class="fas fa-shopping-cart"></i>\n' +
                   '                                                                <span>ADD TO CART</span>\n' +
                   '                                                            </a>';
           }
          else if(data.quantity <= 1) {
               QVAddToCart = QVAddToCart + ' <a href="#" class="theme-btn-1 btn btn-effect-1"\n' +
                   '                                                               title="Out of stock"\n' +
                   '                                                               >\n' +
                   '                                                                <i class="fas fa-shopping-cart"></i>\n' +
                   '                                                                <span style="opacity: 0.8">OUT OF STOCK</span>\n' +
                   '                                                            </a>';
           }

            QVWishList = QVWishList + ' <a href="#" class="" title="Wishlist" data-bs-toggle="modal"\n' +
                '                                                               data-bs-target="#liton_wishlist_modal" onclick="addToWishListQV(\''+data.id+'\',)">\n' +
                '                                                                <i class="far fa-heart"></i>\n' +
                '                                                                <span>Add to Wishlist</span>\n' +
                '                                                            </a>';

            $("#QVAddToCart").html(QVAddToCart);
            $("#QVWishlist").html(QVWishList);
        }
    });
}