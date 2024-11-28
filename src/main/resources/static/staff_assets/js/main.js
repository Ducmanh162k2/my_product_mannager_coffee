
var Jquery;
var orderCode=BigInt(0);
var popHtml = '<div class="container layui-card" style="width: 98%;height: 98%;margin: 1%;background:#F2F2F2">\n' +
    '                <div class="layui-card top-item"\n' +
    '                     style="top:0px;height:100px;margin:0px;color: #0C0C0C;overflow:hidden;text-align: center">\n' +
    '                    <ul style="overflow: hidden;margin: 36px 5px 35px 10px">\n' +
    '                        <li style="float: left">\n' +
    '                            <div style="font-size: 20px;color: red">\n' +
    '                                <span style="height:30px;text-align: center;line-height: 30px">Total:VND</span>\n' +
    '                                <input type="text" id="totalMoney"\n' +
    '                                       style="width: 60px;height: 30px;text-align: center;line-height: 30px;border: none;background:none;color: red" value="0.00" disabled></li>\n' +
    '                        <li style="float: right">\n' +
    '                            <button class="layui-btn" style="background:#AF2825;width:64px;height: 30px;padding:2px 4px;line-height: 30px;text-align: center;font-size: 14px;border-radius: 6px"; id="commit">Xác nhận</button>\n' +
    '                        </li>\n' +
    '                        <li style="float: left;margin-left: 26px">\n' +
    '                           <div style="overflow: hidden;display: inline-block">\n' +
    '                                <span class="input-float" style="height: 30px;text-align: center;line-height: 30px">People: </span>' +
    '                                <input class="input-float people_minus" type="button"\n' +
    '                                       style="width: 25px;font-size:20px;height: 30px;background: none;border: 0px"\n' +
    '                                       value="-" name="minus">\n' +
    '                                <input class="input-float people_number" type="text" name="people_number"\n' +
    '                                       style="width: 50px;height: 30px;border: 0px;text-align: center" disabled\n' +
    '                                       value="1">\n' +
    '                                <input class="input-float people_plus" type="button"\n' +
    '                                       style="width: 25px;font-size:20px;height: 30px;background: none;border: 0px"\n' +
    '                                       value="+">\n' +
    '                           </div>\n' +
    '                        </li>\n' +
    '                    </ul>\n' +
    '                </div>\n' +
    '                <div class="goods-items" id="goodsItems"></div>'
var popDom;


function countTotalMoney(goodsItemsNode) {
    var topItemNode = popDom.find(".top-item");
    var itemArray = goodsItemsNode.children();
    var totalMoneyNode = topItemNode.find("#totalMoney");
    var totalMoney = 0.00;
    itemArray.each(function (index, item) {
        var price = parseFloat(Jquery(item).find("input[name='price']").val());
        var number = parseInt(Jquery(item).find("input[name='number']").val());
        totalMoney += price * number;
    })
    totalMoneyNode.val(parseFloat(totalMoney).toFixed(2));
}


function addGoodsByOrder(products) {
    var goodsItemHtml = parseGoodSView(products);
    var goodsItemsNode = popDom.find(".goods-items");
    goodsItemsNode.append(Jquery(goodsItemHtml));
    countTotalMoney(goodsItemsNode);
}

function parseGoodSView(products) {
    var goodsItemHtml =
        '<ul class="layui-card goods-item">\n' +
        '<input type="hidden" name="id" value="' + products.id + '">\n' +
        '<input type="hidden" name="quantity" value="' + products.quantity + '">\n' +
        '<li class="goods-item-li-other" style=" width: 20%;">\n' +
        '                            <img src="' + products.img + '" class="goods-item-image">\n' +
        '                        </li>\n' +
        '                        <li class="goods-item-li-other" style="padding:20px 0px 20px 3%; width: 22%;">\n' +
        '                            <span class="name"\n' +
        '                                  style="display:inline-block;line-height: 30px;height:30px;font-size:14px;color: #0C0C0C">' + products.name + '</span><br/>\n' +
        '                            <span style="display:inline-block;line-height: 30px;height:30px;color: red">VND<input\n' +
        '                                    type="text" style="width: 30px;border: none;background:none;color: red" name="price"\n' +
        '                                    value=" ' + products.price + '" disabled></span>\n' +
        '                        </li>\n' +
        '                        <li class="goods-item-li-other" style="text-align: center;padding:35px 0px;width: 25%;"\n' +
        '                            disabled="">\n' +
        '                            <div style="overflow: hidden;display: inline-block">\n' +
        '                                <input class="input-float minus" type="button"\n' +
        '                                       style="width: 25px;font-size:20px;height: 30px;background: none;border: 0px"\n' +
        '                                       value="-" name="minus">\n' +
        '                                <input class="input-float number" type="text" name="number"\n' +
        '                                       style="width: 50px;height: 30px;border: 0px;text-align: center" disabled\n' +
        '                                       value="1">\n' +
        '                                <input class="input-float plus" type="button"\n' +
        '                                       style="width: 25px;font-size:20px;height: 30px;background: none;border: 0px"\n' +
        '                                       value="+">\n' +
        '                            </div>\n' +
        '                        </li>\n' +
        '                        <li class="goods-item-li-other" style="text-align: center;width: 15%">\n' +
        '                            <input type="text"\n' +
        '                                   style="width: 90%;height: 30px;margin:35px auto;background:none;border: 0px;text-align: center;color: red"\n' +
        '                                   disabled name="money" value="' + products.price + '"/>\n' +
        '                        </li>\n' +
        '                        <li class="goods-item-li-other" style="text-align: center;width: 15%">\n' +
        '                            <button class="layui-btn layui-btn-primary delete"\n' +
        '                                    style="margin:35px auto;color: #FFFFFF;background: #AF2825;height:30px;line-height:30px;text-align:center;border-radius: 6px;border: 0px;">\n' +
        '                                Xóa\n' +
        '                            </button>\n' +
        '                        </li>\n' +
        '                    </ul>'
    return goodsItemHtml;
}
layui.config({
    base: '/staff_assets/layuiadmin/' // Đường dẫn tới tệp tĩnh của bạn
}).extend({
    index: 'lib/index' // Chỉ định tệp chính
}).use('index');
layui.use(['index', "jquery"], function () {
    var $ = layui.$
        , admin = layui.admin
        , element = layui.element
        , router = layui.router();
    Jquery = $;
    //
    popDom = Jquery(popHtml);
    var topItemNode = popDom.find(".top-item");
    var goodsItemsNode = popDom.find(".goods-items");
    var active = {
        test2: function () {
            top.layui.admin.popupRight({
                id: 'LAY_adminPopupLayerTest'
                , area: '500px'
                , success: function (){
                    $('#' + this.id).css({"width": "100%", "height": "100%", "background": "#f2f2f2"});
                    $('#' + this.id).html(popDom);


                    $('#commit').off('click');

                    $("#commit").on("click", function (e) {
                        layer.confirm('Confirm submission? Cannot modify after submission!',{
                            title: 'Confirm submission',
                            btn: ['Confirm', 'Cancel']
                        }, function (index) {
                            confirm();
                            layer.close(index);
                        });

                        function confirm() {
                            var goodsItemArray = (goodsItemsNode).children(".goods-item");
                            var order = {}
                            var orderDetails = []


                            function orderDetail(quantity, product) {
                                this.quantity = quantity;
                                this.product = product;
                            }

                            for (var i = 0; i < goodsItemArray.size(); i++) {
                                var product = {};
                                product.id = parseInt($(goodsItemArray[i]).find("input[name='id']").val());
                                var quantity = parseInt($(goodsItemArray[i]).find("input[name='number']").val());
                                orderDetails.push(new orderDetail(quantity, product));
                            }

                       //     order.tableCode = $("#deskCode").text();
                            var peopleNode = popDom.find("input[name='people_number']");
                            console.log("peopleNum", $(peopleNode).val());
                            order.orderDetails = orderDetails;
                           // order.peopleNum = parseInt($(peopleNode).val());
                            order.total_money = parseFloat($("#totalMoney").val());
                            var data = JSON.stringify(order);
                            $.ajax({
                                url: '/staff/order/addorder',
                                type: 'POST',
                                data: data,

                                contentType: "application/json; charset=utf-8",
                                dataType: 'JSON',
                                success: function (res) {
                                    if (res.code == 200) {
                                        orderCode = BigInt(res.data);
                                        popDom.empty();

                                        clearAllIframeStyle();
                                        layer.msg("Xác nhận thành công!", {icon: 1})
                                    } else {
                                        layer.msg("Xác nhận thất bại!", {icon: 2})
                                    }
                                }
                            });
                        }
                    })
                    showOrHideCommit();

                    $('.delete').off('click');
                    $(".delete").on("click", function (e) {

                        var goodsItem = $(this).parents(".goods-item")[0];
                        var goodsItems = $(this).parents(".goods-items")[0];
                        goodsItems.removeChild(goodsItem);
                        //
                        for (var i = 0; i < $(".layadmin-iframe").size(); i++) {
                            var childWindow = $(".layadmin-iframe")[i].contentWindow;
                            childWindow.clearChoice($(goodsItem).find("input[name='id']").val());
                        }
                        //
                        var itemMoney = parseFloat($(goodsItem).find("input[name='money']").val());
                        var curtotalMoney = parseFloat($("#totalMoney").val());
                        $("#totalMoney").val((curtotalMoney - itemMoney).toFixed(2));
                        showOrHideCommit();
                    });
                    //
                    $('.plus').off('click');
                    //
                    $(".plus").on("click", function (e) {
                        var goodsItem = $(this).parents(".goods-item");
                        //prev()
                        var currentCount = parseInt($(this).prev().val());
                        var quantity =  $(goodsItem).find("input[name='quantity']").val();
                        // if (currentCount >= 1) {
                        //
                        // }
                        if (currentCount >= quantity) {
                            layer.msg("Not enough count!", {icon: 5});
                        } else {
                            $(this).prev().attr("value", currentCount + 1);
                            var price = parseFloat($(goodsItem).find("input[name='price']").val());
                            $(goodsItem).find("input[name='money']").attr("value", price * (currentCount + 1));
                            var currentMoney = parseFloat($("#totalMoney").val());
                            $("#totalMoney").val((currentMoney + price).toFixed(2));
                        }
                    });
                    //
                    $('.minus').off('click');
                    $(".minus").on("click", function (e) {
                        var goodsItem = $(this).parents(".goods-item");
                        //next()
                        var currentCount = parseInt($(this).next().val());
                        if (currentCount > 1) {
                            $(this).next().attr("value", currentCount - 1);
                            var price = parseFloat($(goodsItem).find("input[name='price']").val());
                            $(goodsItem).find("input[name='money']").attr("value", (price * (currentCount - 1)).toFixed(2));
                            var curTotalMoney = parseFloat($("#totalMoney").val());
                            $("#totalMoney").val((curTotalMoney - price).toFixed(2));
                        }
                    });
                    //
                    $('.people_plus').off('click');

                    $(".people_plus").on("click", function () {
                        //prev()
                        var currentCount = parseInt($(this).prev().val());
                        $(this).prev().attr("value", currentCount + 1);
                    });
                    //
                    $('.people_minus').off('click');
                    $(".people_minus").on("click", function (e) {
                        //next()
                        var currentCount = parseInt($(this).next().val());
                        if (currentCount > 1) {
                            $(this).next().attr("value", currentCount - 1);
                        }
                    });
                }
            });
        }
    };


    $('#goods').on('click', function () {
        var type = $(this).data('type');
        active[type] && active[type].call(this);
    });

    $("#commit_goods").on('click',function (){
        if(orderCode==''){
            layer.msg("Not order yet!",{icon:6});
            return;
        }
        var url = "/staff/order/myOrder?orderCode="+encodeURIComponent(orderCode.toString());
        layer.open({
            type: 2
            , title: 'Submitted Order'
            , content: url
            , maxmin: true
            , anim: 1
            , area: ['900px', '500px']
            , btn: ['Confirm', 'Cancel']
        });
    });

    function showOrHideCommit(){
        var totalMoney = parseFloat($("#totalMoney").val());
        if (totalMoney == 0) {
            $("#commit").hide();
        }else {
            $("#commit").show();
        }
    }


    function clearAllIframeStyle() {
        console.log("iframeSize", $(".layadmin-iframe").size());
        for (var i = 0; i < $(".layadmin-iframe").size(); i++) {
            var childWindow = $(".layadmin-iframe")[i].contentWindow;
            childWindow.clearAllChoice();
        }
    }
});