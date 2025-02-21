package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.*;
import com.cug.cs.overseaprojectinformationsystem.service.*;
import com.cug.cs.overseaprojectinformationsystem.util.CenterNameutil;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author shentong
 * @date 2023/11/13 10:50
 * @description
 */
@RestController
@RequestMapping("/cockpit")
public class LeaderCockpitController {
    @Autowired
    private MarketConditionsService marketConditionsService;
    @Autowired
    private LeadVisitService leadVisitService;
    @Autowired
    private MonthTotalService monthTotalService;
    @Autowired
    private BidService bidService;
    @Autowired
    private HotNewsService hotNewsService;

    //年度指标累计完成进度
    @RequiresPermissions("cockpit:marketConditions:list")
    @GetMapping("/marketConditions")
    public ResData getMarketConditionsList(PageBaseInfo pageBaseInfo) {
        PageBean pageBean = marketConditionsService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @RequiresPermissions("cockpit:marketConditions:add")
    @PostMapping("/marketConditions")
    public ResponseData addMarketConditions(@RequestBody MarketConditions marketConditions) {
        marketConditionsService.add(marketConditions);
        return new ResponseUtil<MarketConditions>().setData(marketConditions,"success");
    }

    @RequiresPermissions("cockpit:marketConditions:update")
    @PutMapping("/marketConditions")
    public ResponseData updateMarketConditions(@RequestBody MarketConditions marketConditions) {
        marketConditionsService.update(marketConditions);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("cockpit:marketConditions:delete")
    @DeleteMapping("/marketConditions")
    public ResponseData deleteMarketConditions(Integer id) {
        marketConditionsService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("cockpit:marketConditions:chart")
    @GetMapping("/chart")
    public ResponseData chartMarketConditions(HttpServletRequest request) {
        Map<String,Object> map1 = new HashMap<>();
        List<String> overseaCenter = CenterNameutil.getCenterName();
        map1.put("overseaCenter", overseaCenter);
        Map<String ,Object> map2 = new HashMap<>();
        List<Integer> annualMetrics = marketConditionsService.getAnnualMetrics(overseaCenter);
        List<Integer> timeSchedule = marketConditionsService.getTimeSchedule(overseaCenter);
        List<Double> done = marketConditionsService.getDone(overseaCenter);
        List<Integer> lastYear = marketConditionsService.getLastYear(overseaCenter);
        map2.put("annualMetrics", annualMetrics);
        map2.put("timeSchedule", timeSchedule);
        map2.put("Done", done);
        map2.put("lastYear", lastYear);
        map1.put("completionProgress", map2);
        return new ResponseUtil<>().setData(map1,"success");
    }

    @RequiresPermissions("cockpit:leadVisits:list")
    @GetMapping("/leadVisits")
    public ResData getLeadVisitsList(PageBaseInfo pageBaseInfo) {
        PageBean pageBean = leadVisitService.getAll(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @PostMapping("/leadVisitsByKey")
    public ResData getLeadVisitsByKeyList(@RequestBody PageBaseInfo pageBaseInfo) {
        PageBean pageBean = leadVisitService.getByKey(pageBaseInfo);
        return new ResUtil<PageBean>().setData(pageBean, "success");
    }

    @RequiresPermissions("cockpit:leadVisits:add")
    @PostMapping("/leadVisits")
    public ResponseData addLeadVisits(@RequestBody LeadVisit leadVisit) {
        leadVisitService.add(leadVisit);
        return new ResponseUtil<LeadVisit>().setData(leadVisit,"success");
    }

    @RequiresPermissions("cockpit:leadVisits:update")
    @PutMapping("/leadVisits")
    public ResponseData updateLeadVisits(@RequestBody LeadVisit leadVisit) {
        leadVisitService.update(leadVisit);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("cockpit:leadVisits:delete")
    @DeleteMapping("/leadVisits")
    public ResponseData deleteLeadVisits(Integer id) {
        leadVisitService.delete(id);
        return new ResponseUtil<>().setData(null,"message");
    }

    @RequiresPermissions("cockpit:newSignChart")
    @PostMapping("/newSignChart")
    public ResponseData listMonthByReq(@Valid @RequestBody DayReq dayReq) {
        List<DayRes> dayResList = monthTotalService.listMonthByReq(dayReq);
        return new ResponseUtil<List<DayRes>>().setData(dayResList, "success");
    }

    @GetMapping("/monthbids")
    public ResponseData monthvisit(){
        ArrayList<String> centerName = CenterNameutil.getCenterName();
        List<Integer> bidNumforMonth = bidService.getBidNumEachMonth(centerName);
        return new ResponseUtil<>().setData(bidNumforMonth);
    }

    @GetMapping("/monthvisits")
    public ResponseData eventmonthvisit(){
        ArrayList<String> centerName = CenterNameutil.getCenterName();
        List<Integer> visitNum = eventService.getVisitNum(centerName);
        return new ResponseUtil<>().setData(visitNum);
    }

    @GetMapping("/news")
    public ResponseData getHotNewsList(HttpServletRequest request) {
        List<News> newsList = hotNewsService.catchNews();
        return new ResponseUtil<List<News>>().setData(newsList, "success");
    }

/*    @Autowired
    private BidService bidService;
    @GetMapping("/totalBidMoney")
    public ResponseData getTotalBidMoney(HttpServletRequest request){
        Map<String,Object> map = new HashMap<>();
        List<String> years = new ArrayList<>();
        Calendar calendar = Calendar.getInstance();
        //获取当前时间，并且往后推5年
        calendar.add(Calendar.YEAR,-5);
        //计算过去5年的日期
        for (int i=0;i<5;i++){
            calendar.add(Calendar.YEAR,1);
            Date date = calendar.getTime();
            years.add(new SimpleDateFormat("yyyy").format(date));
        }
        map.put("Years",years);
        List<Double> Bidmoney = bidService.getBidMoney(years);
        for (int i = 0; i < Bidmoney.size(); i++) {
            double result = Math.round(Bidmoney.get(i) * 10.0)/10.0;
            Bidmoney.set(i,result);
        }
        map.put("totalMoney",Bidmoney);
        return new ResponseUtil<>().setData(map,"success");
    }*/
    /*@GetMapping("/totalBidNum")
    public ResponseData getTotalBidNum(HttpServletRequest request) {
        HashMap<String, Object> map = new HashMap<>();//返回数据
        ArrayList<String> years = new ArrayList<>();
        Calendar calendar = Calendar.getInstance();
        //获取当前时间，并且往后推5年
        calendar.add(Calendar.YEAR,-5);
        //计算过去5年的日期
        for (int i=0;i<5;i++){
            calendar.add(Calendar.YEAR,1);
            Date date = calendar.getTime();
            years.add(new SimpleDateFormat("yyyy").format(date));
        }
        map.put("Years",years);
        //中标和评标数量汇总
        Map<String , Object> bidNum = new HashMap<>();
        List<Integer> successBidNum = bidService.getBidNum(years);
        List<Integer> judgeBidNum = bidService.getJudgeBidNum(years);
        bidNum.put("successBidNum",successBidNum);
        bidNum.put("judgeBidNum",judgeBidNum);
        map.put("totalNum",bidNum);

        return new ResponseUtil<>().setData(map,"success");
    }*/

//    潜在项目线索数？？？？？？？？？
    @Autowired
    private PotproService potproService;
    @GetMapping("/totalPotNum")
    public ResponseData getTotalPotNum(HttpServletRequest request){
        ArrayList<String> centerName = CenterNameutil.getCenterName();
        Map<String,Object> map = new HashMap<>();
        map.put("centerName",centerName);
        List<Integer> potNum = potproService.getPotNum(centerName);
        map.put("potNum",potNum);
        return new ResponseUtil<>().setData(map,"success");
    }

    @Autowired
    private EventService eventService;
    @Autowired
    private PresentationService presentationService;
    @GetMapping("/marketnum")
    public ResponseData getMarketNum(HttpServletRequest request){
        ArrayList<String> centerName = CenterNameutil.getCenterName();
        Map<String,Object> map = new HashMap<>();
        Map<String ,Object> getNum = new HashMap<>();//技术宣讲活动次数、客户来走访活动次数
        map.put("centerName",centerName);
        List<Integer> speechNum = presentationService.getSpeechNum(centerName);
        List<Integer> visitNum = eventService.getVisitNum(centerName);
        getNum.put("speechNum",speechNum);
        getNum.put("visitNum",visitNum);
        map.put("activitiesNum",getNum);
        return new ResponseUtil<>().setData(map,"success");
    }


    @Autowired
    private NewSignService newSignService;
    @GetMapping("/marketactive")
    public ResponseData getMarketActive(HttpServletRequest request){
        Map<String,Object> map = new HashMap<>();
        List<String> months = new ArrayList<>();
        Calendar calendar = Calendar.getInstance();
        //获取当前时间，并且往后推12个月
        calendar.add(Calendar.MONTH,-6);
        //计算过去12
        for (int i=0;i<6;i++){
            calendar.add(Calendar.MONTH,1);
            Date date = calendar.getTime();
            months.add(new SimpleDateFormat("yy/MM").format(date));
        }
        map.put("Months",months);
        List<Double> newSignMoney = newSignService.getNewSignMoneyforMonth(months);
        List<Integer> successBidNum = bidService.getBidNumforMonth(months);
        List<Integer> allBidNum = bidService.getAllBidNumforMonth(months);
        List<Double> marketActive = new ArrayList<>();
        for(int i=0;i<6;i++){
            if(allBidNum.get(i)==0) {marketActive.add(0.0);continue;}//该月没有投标中标.即没有活跃度
            double err = 1;
            if(successBidNum.get(i)==0) {//中标数为零的话,使基数很低.
                err = 0.5;
                successBidNum.set(i,1);
            }
            if(newSignMoney.get(i)==null){
                newSignMoney.set(i,1.0);//该月新签总额为0,设置初始较低值;
            }
            //市场活跃度指数 = （每月中标数量 / 总标数量） * 每月新签合同金额
            Double activeRate = newSignMoney.get(i)*err*((double)successBidNum.get(i)/(double)allBidNum.get(i));
            Double result = Math.round(activeRate*10.0)/10.0;
            marketActive.add(result);
        }
        map.put("marketActive",marketActive);
        return new ResponseUtil<>().setData(map,"success");
    }
}
