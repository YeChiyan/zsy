package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.*;
import com.cug.cs.overseaprojectinformationsystem.service.BidService;
import com.cug.cs.overseaprojectinformationsystem.service.HotNewsService;
import com.cug.cs.overseaprojectinformationsystem.service.MonthTotalService;
import com.cug.cs.overseaprojectinformationsystem.util.CenterNameutil;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author shentong
 * @date 2023/9/18 18:10
 * @description 月度汇总Controller
 */
@RestController
@RequestMapping("/montotal")
public class MonthTotalController {
    @Autowired
    private MonthTotalService monthTotalService;
    @Autowired
    private BidService bidService;


    @PostMapping("/winRates")
    public ResponseData listWinRateByReq(@Valid @RequestBody DayReq dayReq) {
        List<WinRateRes> winRateResList = monthTotalService.listWinRateByReq(dayReq);
        return new ResponseUtil<List<WinRateRes >>().setData(winRateResList, "success");
    }

    @GetMapping("/totalBidNum")
    public ResponseData getTotalBidNum(HttpServletRequest request) {
        HashMap<String, Object> map = new HashMap<>();//返回数据
        List<String> months = monthTotalService.recentSixMonth();
        map.put("Months",months);
        //中标和评标数量汇总
        Map<String , Object> bidNum = new HashMap<>();
        List<Integer> successBidNum = bidService.getBidNum(months);
        List<Integer> judgeBidNum = bidService.getJudgeBidNum(months);
        bidNum.put("successBidNum",successBidNum);
        bidNum.put("judgeBidNum",judgeBidNum);
        map.put("totalNum",bidNum);

        return new ResponseUtil<>().setData(map,"success");
    }

    @GetMapping("/totalBidMoney")
    public ResponseData getTotalBidMoney(HttpServletRequest request){
        Map<String,Object> map = new HashMap<>();
        List<String> months = monthTotalService.recentSixMonth();
        map.put("Months",months);
        List<Double> Bidmoney = bidService.getBidMoney(months);
        for (int i = 0; i < Bidmoney.size(); i++) {
            if (Bidmoney.get(i) != null) {
                double result = Math.round(Bidmoney.get(i) * 10.0) / 10.0;
                Bidmoney.set(i, result);
            }else{
                Bidmoney.set(i, 0.0);
            }
        }
        map.put("totalMoney",Bidmoney);
        return new ResponseUtil<>().setData(map,"success");
    }


    @GetMapping("/newSignMoney")
    public ResponseData getNewSignMoney(HttpServletRequest request){
        Map<String,Object> map = new HashMap<>();
        List<String> months = monthTotalService.recentSixMonth();
        map.put("Months",months);
        List<Double> newSignMoney = monthTotalService.recentSixNewSignMoney(months);
        for (int i = 0; i < newSignMoney.size(); i++) {
            if (newSignMoney.get(i) != null) {
                double result = Math.round(newSignMoney.get(i) * 10.0) / 10.0;
                newSignMoney.set(i, result);
            }else{
                newSignMoney.set(i, 0.0);
            }
        }
        map.put("newSignMoney",newSignMoney);
        return new ResponseUtil<>().setData(map,"success");
    }
    @GetMapping("/potMoney")
    public  ResponseData getPotMoney(HttpServletRequest request){
        Map<String,Object> map = new HashMap<>();
        ArrayList<String> centerList = CenterNameutil.getCenterName();
        map.put("centerList",centerList);
        List<Double> potMoney = monthTotalService.potMoney(centerList);
        for (int i=0;i < potMoney.size();i++){
            if (potMoney.get(i) != null) {
                double result = Math.round(potMoney.get(i) * 10.0) / 10.0;
                potMoney.set(i, result);
            }else{
                potMoney.set(i, 0.0);
            }
        }
        map.put("potMoney",potMoney);
        return new ResponseUtil<>().setData(map,"success");
    }
}
