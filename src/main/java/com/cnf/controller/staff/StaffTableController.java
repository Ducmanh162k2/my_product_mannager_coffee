package com.cnf.controller.staff;

import com.cnf.daos.ProductDTO;
import com.cnf.entity.*;
import com.cnf.services.CategoryService;
import com.cnf.services.ProductService;
import com.cnf.services.TableBookingService;
import com.cnf.ultils.ResultUtil;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@Controller
@RequestMapping("/staff/table")
public class StaffTableController{

    @Autowired
    private TableBookingService deskService;
    @Autowired
    private ProductService goodsService;
    @Autowired
    private CategoryService goodsCategoryService;


    @PostMapping("/login")
    @ResponseBody
    private Result deskLogin(@RequestParam("deskCode") String deskCode,  HttpSession session){
        deskService.booking(deskCode);
        session.setAttribute("deskCode",deskCode);
        return ResultUtil.success();
    }

    @GetMapping("/logout/{deskCode}")
    private String deskLoginOut(@PathVariable("deskCode") String tableCode,HttpSession session){
        deskService.logout(tableCode);
        session.removeAttribute("deskCode");
        return "redirect:/staff/table/desklist";
    }

    @GetMapping("/desklist")
    private String deskList(Model model, @RequestParam(name = "pageNum", required = false, defaultValue = "1") int pageNum){

        int pageSize = 15;
        Page<TableBooking> page = deskService.findPaginated(pageNum, pageSize);
        List<TableBooking> listProduct = page.getContent();

        model.addAttribute("currentPage", pageNum);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("tables", listProduct);
        return "staff/deskPage";
    }

    @GetMapping("/main")
    private String clientMain(Model model){
        model.addAttribute("categoryList",goodsCategoryService.getAllCategories());
        return "staff/main";
    }

    @GetMapping("/goodspage")
    private String goodsPage(){
        return "staff/goodsPage";
    }


    @GetMapping("/goodslist.html/{categoryId}")
    public String goodsList(Model model,@PathVariable("categoryId") Integer categoryId){
        //0，
        if (categoryId==0){
            categoryId=null;
        }
        model.addAttribute("categoryId",categoryId);
        return "/staff/goodsPage";
    }

    @PostMapping("/goodslist.do")
    @ResponseBody
    public Result<Page<ProductDTO>> goodsList(@RequestParam(value = "pageNum",defaultValue = "1") Integer pageNum,
                                              @RequestParam int pageSize,
                                              @RequestParam Long categoryId){
        Page<ProductDTO> productDTOs = goodsService.getProductsByCategory(categoryId, pageNum - 1, pageSize);
        return ResultUtil.success(productDTOs.getContent(), productDTOs.getTotalElements());
    }

    @PostMapping("/updateStatus")
    public ResponseEntity<?> updateStatus(@RequestParam String deskCode) {
        deskService.logout(deskCode);
        return ResponseEntity.ok().body(Map.of("code",200,"msg","Update succesfully!"));
    }


}
